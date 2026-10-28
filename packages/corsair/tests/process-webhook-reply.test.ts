import type { WebhookResponse } from '../core/webhooks';
import { processWebhook } from '../webhooks/index';

// processWebhook must return what the handler decided: its status code and
// success flag, while the existing returnToSender / responseHeaders
// handshakes (Slack url_verification, Asana X-Hook-Secret) stay unchanged.
// processWebhook only walks known provider ids, so the fake handler sits
// under a real id.
function makeCorsair(
	pluginId: string,
	handler: () => Promise<WebhookResponse>,
): Parameters<typeof processWebhook>[0] {
	return {
		[pluginId]: {
			webhooks: { events: { event: { match: () => true, handler } } },
			pluginWebhookMatcher: () => true,
		},
	};
}

const headers = { 'content-type': 'application/json' };

describe('processWebhook keeps the handler reply', () => {
	it('passes a handler 401 / success:false through', async () => {
		const result = await processWebhook(
			makeCorsair('discord', async () => ({
				success: false,
				statusCode: 401,
				error: 'Invalid signature',
			})),
			headers,
			JSON.stringify({ hello: 'world' }),
		);
		expect(result.plugin).toBe('discord');
		const response = result.response as Record<string, unknown>;
		expect({
			statusCode: response['statusCode'],
			success: response['success'],
		}).toEqual({ statusCode: 401, success: false });
	});

	it('compat: Slack-style url_verification challenge echoes unchanged', async () => {
		const body = JSON.stringify({
			type: 'url_verification',
			token: 'x',
			challenge: 'chal-123',
		});
		const result = await processWebhook(
			makeCorsair('slack', async () => ({
				success: true,
				returnToSender: { challenge: 'chal-123' },
			})),
			headers,
			body,
		);
		expect(result.response).toEqual({ challenge: 'chal-123', success: true });
	});

	it('compat: Asana-style responseHeaders handshake is kept', async () => {
		const result = await processWebhook(
			makeCorsair('asana', async () => ({
				success: true,
				responseHeaders: { 'X-Hook-Secret': 'secret-1' },
			})),
			{ ...headers, 'x-hook-secret': 'secret-1' },
			'{}',
		);
		expect(result.responseHeaders).toEqual({ 'X-Hook-Secret': 'secret-1' });
		expect(result.response).toEqual({ success: true });
	});
});
