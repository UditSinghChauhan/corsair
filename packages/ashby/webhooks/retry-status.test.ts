import { createHmac } from 'node:crypto';
import { createCorsair } from 'corsair/core';
// ashby's jest config maps only corsair/core and corsair/http to source;
// the bare 'corsair' and 'corsair/tests' entries resolve to ESM dist, which
// jest can't load here, so import their sources directly.
import {
	createIntegrationAndAccount,
	createTestDatabase,
} from '../../corsair/tests';
import { processWebhook } from '../../corsair/webhooks/index';
import { ashby } from '../index';

// Ashby retries a delivery on any 5xx or timeout (up to 10 attempts) and
// stops on 2xx. The offerDelete handler answers 500 when the local delete
// fails, so the provider retries. processWebhook must pass that status on;
// if it answers 200 the delete is never retried and the offer stays cached.
const secret = 'whsec_test_secret_12345';

const offerDeleteBody = JSON.stringify({
	webhookActionId: 'wh_act_del_1',
	action: 'offerDelete',
	data: { offerId: 'offer_123', applicationId: 'app_123' },
});

function signedHeaders(body: string) {
	const hmac = createHmac('sha256', secret).update(body).digest('hex');
	return {
		'content-type': 'application/json',
		'ashby-signature': `sha256=${hmac}`,
	};
}

// failDelete swaps ctx.db.offers.deleteById for one that throws, through
// the plugin's public webhookHooks `before` hook, so the real handler runs
// against a store whose delete fails.
async function buildCorsair(failDelete: boolean) {
	const testDb = createTestDatabase();
	await createIntegrationAndAccount(testDb.db, 'ashby');
	const deleteCalls: string[] = [];
	const corsair = createCorsair({
		plugins: [
			ashby({
				webhookSecret: secret,
				webhookHooks: {
					offer: {
						delete: {
							before: (ctx, request) => {
								const offers = ctx.db.offers;
								const deleteById: typeof offers.deleteById = async (id) => {
									deleteCalls.push(id);
									if (failDelete) throw new Error('db unavailable');
									return offers.deleteById(id);
								};
								return {
									ctx: {
										...ctx,
										db: { ...ctx.db, offers: { ...offers, deleteById } },
									},
									args: request,
									continue: true as const,
								};
							},
						},
					},
				},
			}),
		],
		database: testDb.db,
		kek: process.env.CORSAIR_KEK ?? 'test-kek-0123456789abcdef0123456789abcdef',
	});
	return { corsair, testDb, deleteCalls };
}

describe('ashby offerDelete through processWebhook', () => {
	it('a failed local delete answers 500 so Ashby retries', async () => {
		const { corsair, testDb, deleteCalls } = await buildCorsair(true);
		try {
			const result = await processWebhook(
				corsair,
				signedHeaders(offerDeleteBody),
				offerDeleteBody,
			);
			expect(result.plugin).toBe('ashby');
			expect(result.action).toBe('offer.delete');
			expect(deleteCalls).toEqual(['offer_123']);
			const response = result.response as Record<string, unknown>;
			expect({
				statusCode: response['statusCode'],
				success: response['success'],
			}).toEqual({ statusCode: 500, success: false });
		} finally {
			testDb.cleanup();
		}
	});

	it('control: a successful delete answers success with no error status', async () => {
		const { corsair, testDb, deleteCalls } = await buildCorsair(false);
		try {
			const result = await processWebhook(
				corsair,
				signedHeaders(offerDeleteBody),
				offerDeleteBody,
			);
			expect(result.action).toBe('offer.delete');
			expect(deleteCalls).toEqual(['offer_123']);
			const response = result.response as Record<string, unknown>;
			expect(response['success']).toBe(true);
			expect(response['statusCode'] ?? 200).toBe(200);
		} finally {
			testDb.cleanup();
		}
	});

	it('control: the bound handler itself returns 500 / success false', async () => {
		const { corsair, testDb } = await buildCorsair(true);
		try {
			const result = await corsair.ashby.webhooks.offer.delete.handler({
				payload: JSON.parse(offerDeleteBody),
				headers: signedHeaders(offerDeleteBody),
				rawBody: offerDeleteBody,
			});
			expect(result).toMatchObject({ success: false, statusCode: 500 });
		} finally {
			testDb.cleanup();
		}
	});
});

// Catch path: a handler that throws is reported as success:false, but with
// no status, so a caller that forwards result.response still answers 200.
describe('processWebhook when the handler throws', () => {
	it('returns success false and no statusCode', async () => {
		const corsair: Parameters<typeof processWebhook>[0] = {
			ashby: {
				webhooks: {
					offer: {
						delete: {
							match: () => true,
							handler: async () => {
								throw new Error('db unavailable');
							},
						},
					},
				},
				pluginWebhookMatcher: () => true,
			},
		};
		const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
		try {
			const result = await processWebhook(
				corsair,
				signedHeaders(offerDeleteBody),
				offerDeleteBody,
			);
			expect(result.plugin).toBe('ashby');
			expect(result.response).toEqual({
				success: false,
				error: 'db unavailable',
			});
			expect((result.response as Record<string, unknown>)['statusCode']).toBe(
				undefined,
			);
		} finally {
			errorSpy.mockRestore();
		}
	});
});

// Docs (concepts/webhooks.mdx) call a `before` hook's `continue: false` a
// silent skip: the handler does not run and nothing is reported as an error.
describe('processWebhook when a before hook returns continue: false', () => {
	it('skips silently: no error, no success:false, no console.error', async () => {
		const testDb = createTestDatabase();
		await createIntegrationAndAccount(testDb.db, 'ashby');
		const corsair = createCorsair({
			plugins: [
				ashby({
					webhookSecret: secret,
					webhookHooks: {
						offer: {
							delete: {
								before: (ctx, request) => ({
									ctx,
									args: request,
									continue: false,
								}),
							},
						},
					},
				}),
			],
			database: testDb.db,
			kek:
				process.env.CORSAIR_KEK ?? 'test-kek-0123456789abcdef0123456789abcdef',
		});
		const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
		try {
			const result = await processWebhook(
				corsair,
				signedHeaders(offerDeleteBody),
				offerDeleteBody,
			);
			expect(result.plugin).toBe('ashby');
			expect(result.action).toBe('offer.delete');
			const response = result.response as Record<string, unknown>;
			const handlerErrorLogged = errorSpy.mock.calls.some(
				(call) =>
					typeof call[0] === 'string' &&
					call[0].includes('Error executing webhook handler'),
			);
			expect({
				success: response['success'],
				error: response['error'],
				statusCode: response['statusCode'],
				handlerErrorLogged,
			}).toEqual({
				success: true,
				error: undefined,
				statusCode: undefined,
				handlerErrorLogged: false,
			});
		} finally {
			errorSpy.mockRestore();
			testDb.cleanup();
		}
	});
});
