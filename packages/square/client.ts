import type { ApiRequestOptions, OpenAPIConfig } from 'corsair/http';
import { ApiError, request } from 'corsair/http';
import { z } from 'zod';

// Square sends this header on every request; without it Square falls back to
// the version pinned on the seller's application in the Developer Console.
export const SQUARE_API_VERSION = '2026-09-16';

// Square's production and sandbox hosts. Sandbox access tokens only work on
// the sandbox host and production tokens only on production.
export const SQUARE_BASE_URLS = {
	production: 'https://connect.squareup.com',
	sandbox: 'https://connect.squareupsandbox.com',
} as const;

export type SquareEnvironment = keyof typeof SQUARE_BASE_URLS;

// Square error bodies are `{ errors: [{ category, code, detail?, field? }] }`.
const SquareErrorBodySchema = z.object({
	errors: z.array(
		z.object({
			category: z.string(),
			code: z.string(),
			detail: z.string().optional(),
			field: z.string().optional(),
		}),
	),
});

export type SquareErrorEntry = z.infer<
	typeof SquareErrorBodySchema
>['errors'][number];

/**
 * Square's `errors[]` from a failed call: core's ApiError keeps Square's body
 * as `body`, and its message is only the HTTP status text. Returns no entries
 * for anything else, or for a body that is not in Square's shape. Reads the
 * error; never changes it.
 */
// unknown: callers pass whatever a rejected call threw.
export function squareErrors(error: unknown): SquareErrorEntry[] {
	if (!(error instanceof ApiError)) return [];
	const parsed = SquareErrorBodySchema.safeParse(error.body);
	return parsed.success ? parsed.data.errors : [];
}

/**
 * The request got no response from Square: the connection dropped or timed
 * out. Square may or may not have run it. The original error is the `cause`.
 */
export class SquareNetworkError extends Error {
	// unknown: whatever fetch rejected with (a TypeError, a DOMException, ...).
	constructor(cause: unknown) {
		super(
			`Square request got no response: ${cause instanceof Error ? cause.message : String(cause)}`,
			{ cause },
		);
		this.name = 'SquareNetworkError';
	}
}

type QueryValue = string | number | boolean | undefined;

export type SquareRequestOptions = {
	method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
	// unknown: a request body is whatever JSON the operation's input schema
	// produced; it is validated before it gets here.
	body?: Record<string, unknown>;
	/** Sent as multipart/form-data; fetch sets the boundary. */
	formData?: FormData;
	/** Values for `{name}` placeholders in the endpoint; each is URI-encoded. */
	path?: Record<string, string | number>;
	query?: Record<string, QueryValue>;
	environment?: SquareEnvironment;
};

/**
 * Sends one request to Square. Core's request() retries a 429 up to three
 * times and honours Retry-After; any other failure is thrown as core's
 * ApiError, unchanged, so its status and retryAfter reach the error handlers
 * and core. A request that got no response at all becomes a
 * SquareNetworkError. Whether a 5xx or a network failure is retried is the
 * error handlers' call (error-handlers.ts), by operation.
 */
export async function makeSquareRequest<T>(
	endpoint: string,
	token: string,
	options: SquareRequestOptions = {},
): Promise<T> {
	const {
		method = 'GET',
		body,
		formData,
		path,
		query,
		environment = 'production',
	} = options;

	// `request` turns TOKEN into `Authorization: Bearer <token>`.
	const config: OpenAPIConfig = {
		BASE: SQUARE_BASE_URLS[environment],
		VERSION: '1.0.0',
		WITH_CREDENTIALS: false,
		CREDENTIALS: 'omit',
		TOKEN: token,
		HEADERS: { 'Square-Version': SQUARE_API_VERSION },
		ENCODE_PATH: encodeURIComponent,
	};

	const requestOptions: ApiRequestOptions = {
		method,
		url: endpoint,
		path,
		query,
		// A FormData body goes out as is; fetch sets the multipart boundary.
		...(formData
			? { body: formData }
			: body !== undefined
				? { body, mediaType: 'application/json' }
				: {}),
	};

	try {
		return await request<T>(config, requestOptions);
	} catch (error) {
		if (error instanceof ApiError) throw error;
		throw new SquareNetworkError(error);
	}
}

/** What the endpoints pass in: the resolved token and, for OAuth, a way to refresh it. */
export type SquareAuthContext = {
	key: string;
	/**
	 * Set by the plugin's keyBuilder for OAuth connections (core's
	 * getOAuthAccessToken); absent for an API key or a static `key` option.
	 */
	_refreshAuth?: () => Promise<string>;
};

/**
 * Sends the request with `auth.key`. On a 401 with a refresh available it
 * refreshes the token and sends the request once more; a second 401 is the
 * caller's error. A 401 means Square rejected the request before running it,
 * so sending it again cannot repeat a side effect, keyless POSTs included.
 */
export async function makeAuthenticatedSquareRequest<T>(
	endpoint: string,
	auth: SquareAuthContext,
	options: SquareRequestOptions = {},
): Promise<T> {
	try {
		return await makeSquareRequest<T>(endpoint, auth.key, options);
	} catch (error) {
		if (
			error instanceof ApiError &&
			error.status === 401 &&
			auth._refreshAuth
		) {
			const freshToken = await auth._refreshAuth();
			return await makeSquareRequest<T>(endpoint, freshToken, options);
		}
		throw error;
	}
}
