import { bindEndpointsRecursively } from '../core/endpoints/bind';
import type { CorsairPlugin, EndpointMetaEntry } from '../core/plugins';
import type { HubConfig } from '../hub/types';

/**
 * One row per exit path of a bound managed call. The invariant every row
 * checks: for each idempotency key the SDK sends at most one terminal report,
 * only for a key Hub charged, and the report matches what the provider did.
 * Rows assert the safe expectation; a red row is a cell the stack misses.
 */

// Binding reads only the plugin's id and options.authType (to pick managed
// pricing), so the rest of a CorsairPlugin is left out of this fixture.
const plugin = {
	id: 'firecrawl',
	options: { authType: 'managed_pricing' as const },
} as unknown as CorsairPlugin;

const META: Record<string, EndpointMetaEntry> = {
	'crawl.start': { riskLevel: 'write' },
	'crawl.get': { riskLevel: 'read' },
	'scrape.run': { riskLevel: 'read' },
};

const KINDS = [
	{
		plugin: 'firecrawl',
		operation: 'crawl.start',
		role: 'start',
		id_path: 'id',
		status_operation: 'crawl.get',
		cap_path: 'limit',
		cap_max: 1000,
	},
	{
		plugin: 'firecrawl',
		operation: 'crawl.get',
		role: 'status',
		id_arg: 'id',
		status_path: 'status',
	},
];

// Job kinds are cached per Hub address for the whole module, so each test
// gets its own address and its own table.
let hubSeq = 0;
function freshHub(runtimeProofKey?: string): HubConfig {
	hubSeq++;
	return {
		projectApiKey: 'ck_cloud_test',
		signingSecret: 'signing-secret',
		apiUrl: `https://hub-${hubSeq}.test`,
		instanceKey: 'main',
		...(runtimeProofKey ? { runtimeProofKey } : {}),
	};
}

// unknown: endpoints answer with whatever the row hands them.
type Fn = (args: unknown) => Promise<unknown>;
type Api = { crawl: { start: Fn; get: Fn }; scrape: { run: Fn } };

// unknown: each endpoint answers with the canned result the row gives it, and
// hooks are any endpoint hooks, as bindEndpointsRecursively takes them.
function bind(
	hub: HubConfig,
	results: Record<string, () => Promise<unknown>>,
	hooks?: Record<string, unknown>,
): Api {
	const tree: Record<string, unknown> = {};
	const endpoint = (path: string) => async () => results[path]!();
	bindEndpointsRecursively({
		endpoints: {
			crawl: { start: endpoint('crawl.start'), get: endpoint('crawl.get') },
			scrape: { run: endpoint('scrape.run') },
		},
		hooks,
		ctx: {},
		tree,
		pluginId: 'firecrawl',
		errorHandlers: {},
		currentPath: [],
		endpointMeta: META,
		tenantId: 'me',
		hubConfig: hub,
		plugin,
	});
	// bindEndpointsRecursively writes the bound function at each path of
	// `endpoints` above, so the tree has exactly the Api shape.
	return tree as Api;
}

// unknown: request bodies are parsed JSON, read with matchers.
type Sent = {
	url: string;
	body: Record<string, unknown>;
	headers: Record<string, string>;
};
type Answer = 'ok' | 'unauthorized' | 'stall';

function mockHub({
	kinds = true,
	usagePath,
	job,
	reports = 'ok',
}: {
	kinds?: boolean;
	usagePath?: string;
	// unknown: the job descriptor Hub's credentials answer carries, as JSON.
	job?: Record<string, unknown>;
	/** How Hub answers /usage/outcome, /jobs and /jobs/report. */
	reports?: Answer;
} = {}) {
	const sent: Sent[] = [];
	jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
		const url = String(input);
		const headers = Object.fromEntries(new Headers(init?.headers).entries());
		sent.push({ url, body: JSON.parse(String(init?.body ?? '{}')), headers });
		const json = (status: number, body: unknown) =>
			new Response(JSON.stringify(body), {
				status,
				headers: { 'content-type': 'application/json' },
			});
		if (url.endsWith('/managed-pricing/job-kinds')) {
			return kinds
				? json(200, { kinds: KINDS })
				: json(404, { error: 'Not found' });
		}
		if (url.endsWith('/managed-pricing/credentials')) {
			return json(200, {
				api_key: 'fc-test-key',
				expires_in: 300,
				...(usagePath ? { usage_path: usagePath } : {}),
				...(job ? { job } : {}),
			});
		}
		if (reports === 'unauthorized') {
			return json(401, { error: 'runtime proof required' });
		}
		if (reports === 'stall') {
			// A Hub that never answers: only the request's own deadline ends it.
			return new Promise<Response>((_, reject) => {
				init?.signal?.addEventListener('abort', () =>
					reject(init.signal?.reason),
				);
			});
		}
		return json(200, { ok: true });
	});
	const to = (path: string) => sent.filter((s) => s.url.endsWith(path));
	return {
		credentials: () => to('/managed-pricing/credentials'),
		outcomes: () => to('/managed-pricing/usage/outcome'),
		starts: () => to('/managed-pricing/jobs'),
		reports: () => to('/managed-pricing/jobs/report'),
		keyOf: (s: Sent | undefined) => s?.body.idempotencyKey,
	};
}

afterEach(() => {
	jest.restoreAllMocks();
});

describe('C0 controls (each PR’s own cells)', () => {
	it('flat success: one key request, no report', async () => {
		const hub = freshHub();
		const h = mockHub();
		const api = bind(hub, { 'scrape.run': async () => ({ ok: true }) });
		await api.scrape.run({});
		expect(h.credentials()).toHaveLength(1);
		expect(h.outcomes()).toHaveLength(0);
	});

	it('endpoint throws: one failed report under the charged key', async () => {
		const hub = freshHub();
		const h = mockHub();
		const api = bind(hub, {
			'scrape.run': async () => {
				throw new Error('provider 500');
			},
		});
		await expect(api.scrape.run({})).rejects.toThrow('provider 500');
		expect(h.outcomes()).toHaveLength(1);
		expect(h.outcomes()[0]?.body).toMatchObject({ outcome: 'failed' });
		expect(h.keyOf(h.outcomes()[0])).toBe(h.keyOf(h.credentials()[0]));
	});

	it('after hook throws: one failed report', async () => {
		const hub = freshHub();
		const h = mockHub();
		const api = bind(
			hub,
			{ 'scrape.run': async () => ({ ok: true }) },
			{
				scrape: {
					run: {
						after: async () => {
							throw new Error('cache write failed');
						},
					},
				},
			},
		);
		await expect(api.scrape.run({})).rejects.toThrow('cache write failed');
		expect(h.outcomes()).toHaveLength(1);
		expect(h.outcomes()[0]?.body).toMatchObject({ outcome: 'failed' });
	});

	it('before hook continue:false: one failed report', async () => {
		const hub = freshHub();
		const h = mockHub();
		const api = bind(
			hub,
			{ 'scrape.run': async () => ({ ok: true }) },
			{
				scrape: {
					run: {
						// unknown: hooks receive any context and arguments.
						before: async (ctx: unknown, args: unknown) => ({
							ctx,
							args,
							continue: false,
						}),
					},
				},
			},
		);
		await api.scrape.run({});
		expect(h.outcomes()).toHaveLength(1);
		expect(h.outcomes()[0]?.body).toMatchObject({ outcome: 'failed' });
	});
});

describe('M2 per-unit start: one key, one terminal report', () => {
	it('sends a usage settle or a job start for the key, not both', async () => {
		const hub = freshHub();
		const h = mockHub({ usagePath: 'creditsUsed' });
		const api = bind(hub, {
			'crawl.start': async () => ({ id: 'j1', creditsUsed: 3 }),
		});
		await api.crawl.start({ url: 'https://example.com', limit: 50 });
		const key = h.keyOf(h.credentials()[0]);
		const settles = h
			.outcomes()
			.filter((s) => s.body.outcome === 'succeeded' && h.keyOf(s) === key);
		const starts = h.starts().filter((s) => h.keyOf(s) === key);
		console.log(`M2 settles=${settles.length} starts=${starts.length}`);
		expect(settles.length + starts.length).toBeLessThanOrEqual(1);
	});
});

describe('M3 status read with a usage path', () => {
	it('sends no usage settle for an uncharged read', async () => {
		const hub = freshHub();
		const h = mockHub({ usagePath: 'creditsUsed' });
		const api = bind(hub, {
			'crawl.get': async () => ({ status: 'completed', creditsUsed: 12 }),
		});
		await api.crawl.get({ id: 'j1' });
		const key = h.keyOf(h.credentials()[0]);
		const settles = h
			.outcomes()
			.filter((s) => s.body.outcome === 'succeeded' && h.keyOf(s) === key);
		console.log(
			`M3 outcomes=${h.outcomes().length} settles=${settles.length} jobReports=${h.reports().length}`,
		);
		expect(settles).toHaveLength(0);
	});
});

describe('M5 a start without a numeric cap', () => {
	// Safe: the cap reaches Hub, or the SDK refuses the call itself with a
	// clear error. Unsafe: the key request goes out with no cap at all.
	async function startWith(args: Record<string, unknown>) {
		const hub = freshHub();
		const h = mockHub();
		const api = bind(hub, { 'crawl.start': async () => ({ id: 'j1' }) });
		let refused: unknown;
		try {
			await api.crawl.start(args);
		} catch (error) {
			refused = error;
		}
		const body = h.credentials()[0]?.body;
		const capSent = body !== undefined && 'cap' in body;
		console.log(
			`M5 ${JSON.stringify(args)} capSent=${capSent} cap=${JSON.stringify(body?.cap)} refused=${refused instanceof Error ? refused.message : 'no'}`,
		);
		return { capSent, refused: refused !== undefined && !h.credentials()[0] };
	}

	it('limit as a string', async () => {
		const r = await startWith({ url: 'https://example.com', limit: '50' });
		expect(r.capSent || r.refused).toBe(true);
	});

	it('limit omitted', async () => {
		const r = await startWith({ url: 'https://example.com' });
		expect(r.capSent || r.refused).toBe(true);
	});
});

describe('M7 self-hosted runtime (no runtimeProofKey): cost of reports', () => {
	// Measurement rows: they record wall time and request counts and assert
	// only that the call itself still behaves.
	const RUNS = 5;
	const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[RUNS >> 1];

	async function time(answer: Answer, op: 'fail' | 'start') {
		const ms: number[] = [];
		let counts = '';
		for (let i = 0; i < RUNS; i++) {
			jest.restoreAllMocks();
			const hub = freshHub();
			const h = mockHub({ reports: answer });
			const api = bind(hub, {
				'scrape.run': async () => {
					throw new Error('provider 500');
				},
				'crawl.start': async () => ({ id: 'j1' }),
			});
			const t0 = performance.now();
			if (op === 'fail') {
				await expect(api.scrape.run({})).rejects.toThrow('provider 500');
			} else {
				await api.crawl.start({ url: 'https://example.com', limit: 50 });
			}
			ms.push(Math.round(performance.now() - t0));
			const signed = [...h.outcomes(), ...h.starts()].filter(
				(s) => 'x-corsair-runtime-proof' in s.headers,
			).length;
			counts = `outcomes=${h.outcomes().length} starts=${h.starts().length} signed=${signed}`;
		}
		console.log(
			`M7 ${op} hub=${answer} median=${median(ms)}ms runs=${ms.join(',')} ${counts}`,
		);
	}

	for (const answer of ['ok', 'unauthorized', 'stall'] as const) {
		it(`failing flat call, reports answer ${answer}`, async () => {
			await time(answer, 'fail');
		}, 60_000);
		it(`successful crawl.start, reports answer ${answer}`, async () => {
			await time(answer, 'start');
		}, 120_000);
	}
});

describe('M11 a per-unit settle at zero', () => {
	it('provider result reports 0 units', async () => {
		const hub = freshHub();
		const h = mockHub({ usagePath: 'creditsUsed' });
		const api = bind(hub, {
			'scrape.run': async () => ({ ok: true, creditsUsed: 0 }),
		});
		await api.scrape.run({});
		const settles = h.outcomes().filter((s) => s.body.outcome === 'succeeded');
		console.log(
			`M11a settles=${JSON.stringify(settles.map((s) => s.body.usage))}`,
		);
		// Recorded, not asserted: 0 from the provider may be a real 0. Hub's call.
		expect(settles.length).toBeLessThanOrEqual(1);
	});

	// Skipped: endpoint hooks are set in createCorsair, which Cloud users don't
	// control, so no Cloud call reaches this row. Kept to record the ordering.
	it.skip('an after hook that rewrites the usage field does not change the settle', async () => {
		const hub = freshHub();
		const h = mockHub({ usagePath: 'creditsUsed' });
		const api = bind(
			hub,
			{ 'scrape.run': async () => ({ ok: true, creditsUsed: 7 }) },
			{
				scrape: {
					run: {
						// unknown: hooks receive any context, result and pass-through.
						after: async (_ctx: unknown, res: unknown) => {
							(res as Record<string, unknown>).creditsUsed = 0;
						},
					},
				},
			},
		);
		await api.scrape.run({});
		const settles = h.outcomes().filter((s) => s.body.outcome === 'succeeded');
		console.log(
			`M11b settles=${JSON.stringify(settles.map((s) => s.body.usage))}`,
		);
		expect(settles.map((s) => s.body.usage)).toEqual([{ units: 7 }]);
	});
});

// F1: the key request is the one Hub call with
// no deadline. #1973 bounds the job-kinds read to 2 s because "every managed
// call waits on this read"; since #1964 every managed call also waits on
// /managed-pricing/credentials, uncached. Safe expectation: a Hub that never
// answers the key request fails the call within a bounded time.
describe('F1 a Hub that never answers the key request', () => {
	it('fails the call within 10 s instead of hanging', async () => {
		const hub = freshHub();
		jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
			const url = String(input);
			if (url.endsWith('/managed-pricing/job-kinds')) {
				return new Response(JSON.stringify({ kinds: [] }), {
					status: 200,
					headers: { 'content-type': 'application/json' },
				});
			}
			// Credentials: never answers; only an abort signal can end it.
			return new Promise<Response>((_, reject) => {
				init?.signal?.addEventListener('abort', () =>
					reject(init.signal?.reason),
				);
			});
		});
		const api = bind(hub, { 'scrape.run': async () => ({ success: true }) });
		const started = Date.now();
		const outcome = await Promise.race([
			api.scrape.run({ url: 'https://example.com' }).then(
				() => 'resolved',
				() => 'rejected',
			),
			new Promise<string>((resolve) =>
				setTimeout(() => resolve('still pending'), 10_000),
			),
		]);
		console.log(`[F1] after ${Date.now() - started} ms: ${outcome}`);
		expect(outcome).toBe('rejected');
	}, 15_000);
});
