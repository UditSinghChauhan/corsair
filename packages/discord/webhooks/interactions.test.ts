import crypto from 'node:crypto';
import { createCorsair } from 'corsair/core';
// discord's jest config maps only corsair/core and corsair/http to source;
// the bare 'corsair' and 'corsair/tests' entries resolve to ESM dist, which
// jest can't load here, so import their sources directly.
import {
	createIntegrationAndAccount,
	createTestDatabase,
} from '../../corsair/tests';
import { processWebhook } from '../../corsair/webhooks/index';
import { discord } from '../index';

// Discord signs `timestamp + rawBody` with the application's Ed25519 key and
// expects the interaction callback as the HTTP response body:
// PING -> 200 {type:1}; component -> a callback type such as 6
// (DEFERRED_UPDATE_MESSAGE).
const { publicKey: pub, privateKey } = crypto.generateKeyPairSync('ed25519');
const publicKeyHex = pub
	.export({ format: 'der', type: 'spki' })
	.subarray(-32)
	.toString('hex');

function signedHeaders(body: string) {
	const timestamp = String(Math.floor(Date.now() / 1000));
	const signature = crypto.sign(
		null,
		Buffer.from(timestamp + body, 'utf8'),
		privateKey,
	);
	return {
		'content-type': 'application/json',
		'x-signature-ed25519': signature.toString('hex'),
		'x-signature-timestamp': timestamp,
	};
}

async function buildCorsair() {
	const testDb = createTestDatabase();
	await createIntegrationAndAccount(testDb.db, 'discord');
	const corsair = createCorsair({
		plugins: [discord({ key: 'x', publicKey: publicKeyHex })],
		database: testDb.db,
		kek: process.env.CORSAIR_KEK ?? 'test-kek-0123456789abcdef0123456789abcdef',
	});
	return { corsair, testDb };
}

const base = {
	id: '1100000000000000001',
	application_id: '1100000000000000002',
	token: 'interaction-token',
	version: 1,
};

const pingBody = JSON.stringify({ ...base, type: 1 });

const componentBody = JSON.stringify({
	...base,
	type: 3,
	guild_id: '1100000000000000003',
	channel_id: '1100000000000000004',
	member: { user: { id: '1100000000000000005', username: 'tester' } },
	message: { id: '1100000000000000006', channel_id: '1100000000000000004' },
	data: { custom_id: 'b1', component_type: 2 },
});

describe('discord interactions through processWebhook', () => {
	it('PING with a valid signature answers 200 with {type:1}', async () => {
		const { corsair, testDb } = await buildCorsair();
		try {
			const result = await processWebhook(
				corsair,
				signedHeaders(pingBody),
				pingBody,
			);
			expect(result.plugin).toBe('discord');
			expect(result.action).toBe('interactions.ping');
			const response = result.response as Record<string, unknown>;
			expect(response).toMatchObject({ type: 1 });
			expect(response['statusCode'] ?? 200).toBe(200);
		} finally {
			testDb.cleanup();
		}
	});

	it('MESSAGE_COMPONENT answers with callback type 6', async () => {
		const { corsair, testDb } = await buildCorsair();
		try {
			const result = await processWebhook(
				corsair,
				signedHeaders(componentBody),
				componentBody,
			);
			expect(result.action).toBe('interactions.messageComponent');
			const response = result.response as Record<string, unknown>;
			expect(response['type']).toBe(6);
		} finally {
			testDb.cleanup();
		}
	});
});

// Control: the discord handlers already decide the right status and PONG;
// the expectations above fail only because processWebhook drops them.
describe('discord interaction handlers called directly (control)', () => {
	function request(body: string) {
		return {
			payload: JSON.parse(body),
			headers: signedHeaders(body),
			rawBody: body,
		};
	}

	it('ping handler returns data {type:1} for a valid signature', async () => {
		const { corsair, testDb } = await buildCorsair();
		try {
			const result = await corsair.discord.webhooks.interactions.ping.handler(
				request(pingBody),
			);
			expect(result).toMatchObject({ success: true, data: { type: 1 } });
		} finally {
			testDb.cleanup();
		}
	});
});
