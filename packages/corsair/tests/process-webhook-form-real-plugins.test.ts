/**
 * processWebhook with REAL plugins on a
 * form-encoded string body. Controls send the same event as an object body, so a
 * red row means the string path, not this harness.
 *
 * "verified" comes from a real webhookHooks.after hook: core calls it only when
 * the handler returned success: true. processWebhook's own result can't show
 * this, because it reports { success: true } for a handler's 401 as well.
 */
import { createHmac } from 'node:crypto';
import { airtable } from '../../airtable/index';
import { box } from '../../box/index';
import { hubspot } from '../../hubspot/index';
import { mailchimp } from '../../mailchimp/index';
import { posthog } from '../../posthog/index';
import { telegram } from '../../telegram/index';
import { twilio } from '../../twilio/index';
import { createCorsair } from '../core';
import { processWebhook } from '../webhooks/index';

const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const KEK = 'test-kek-form-real-plugins';
const SECRET = 'form-secret';
const AUTH_TOKEN = 'twilio-test-token';
const TWILIO_URL = 'https://app.example.com/api/webhooks';

const mailchimpFields = {
	type: 'subscribe',
	fired_at: '2026-11-06 10:00:00',
	'data[id]': '8a25ff1d98',
	'data[list_id]': 'a1b2c3',
	'data[email]': 'api@mailchimp.com',
	'data[email_type]': 'html',
	'data[ip_opt]': '10.20.10.30',
};
const mailchimpForm = new URLSearchParams(mailchimpFields).toString();
const mailchimpObject = {
	type: 'subscribe',
	fired_at: '2026-11-06 10:00:00',
	data: {
		id: '8a25ff1d98',
		list_id: 'a1b2c3',
		email: 'api@mailchimp.com',
		email_type: 'html',
		ip_opt: '10.20.10.30',
	},
};

const twilioFields: Record<string, string> = {
	AccountSid: 'AC1234',
	From: '+15005550006',
	MessageSid: 'SM1234',
	MessageStatus: 'delivered',
	SmsStatus: 'delivered',
	To: '+15005550009',
};
const twilioForm = new URLSearchParams(twilioFields).toString();

/** A correct X-Twilio-Signature: Twilio's documented HMAC over URL + sorted params. */
function twilioHeaders() {
	const data = Object.keys(twilioFields)
		.sort()
		.reduce((text, key) => `${text}${key}${twilioFields[key]}`, TWILIO_URL);
	return {
		...FORM,
		'x-forwarded-url': TWILIO_URL,
		'x-twilio-signature': createHmac('sha1', AUTH_TOKEN)
			.update(data)
			.digest('base64'),
	};
}

function mailchimpPlugin(onVerified: () => void) {
	return mailchimp({
		webhookSecret: SECRET,
		webhookHooks: { subscribe: { after: async () => onVerified() } },
	});
}

function twilioPlugin(onVerified: () => void) {
	return twilio({
		webhookSecret: AUTH_TOKEN,
		webhookHooks: {
			message: { statusUpdate: { after: async () => onVerified() } },
		},
	});
}

beforeEach(() => {
	// Offline: no plugin may reach a provider. Handler logging to a missing db stays local.
	globalThis.fetch = () => Promise.reject(new Error('network blocked in test'));
});

describe('controls: same events as object bodies', () => {
	it('C1 mailchimp object body routes and verifies', async () => {
		const verified = jest.fn();
		const corsair = createCorsair({
			plugins: [mailchimpPlugin(verified)],
			kek: KEK,
		});
		const result = await processWebhook(corsair, FORM, mailchimpObject, {
			secret: SECRET,
		});
		expect([result.plugin, result.action]).toEqual(['mailchimp', 'subscribe']);
		expect(verified).toHaveBeenCalledTimes(1);
	});

	it('C2 twilio object body routes and verifies', async () => {
		const verified = jest.fn();
		const corsair = createCorsair({
			plugins: [twilioPlugin(verified)],
			kek: KEK,
		});
		const result = await processWebhook(corsair, twilioHeaders(), twilioFields);
		expect([result.plugin, result.action]).toEqual([
			'twilio',
			'message.statusUpdate',
		]);
		expect(verified).toHaveBeenCalledTimes(1);
	});
});

describe('form-encoded string bodies', () => {
	it('R1 mailchimp only: routed to mailchimp and verified', async () => {
		const verified = jest.fn();
		const corsair = createCorsair({
			plugins: [mailchimpPlugin(verified)],
			kek: KEK,
		});
		const result = await processWebhook(corsair, FORM, mailchimpForm, {
			secret: SECRET,
		});
		expect([result.plugin, result.action]).toEqual(['mailchimp', 'subscribe']);
		expect(verified).toHaveBeenCalledTimes(1);
	});

	it('R2 mailchimp + airtable, box, hubspot (their webhook match throws when called directly; all before mailchimp): routed to mailchimp', async () => {
		const verified = jest.fn();
		const corsair = createCorsair({
			plugins: [airtable(), box(), hubspot(), mailchimpPlugin(verified)],
			kek: KEK,
		});
		const result = await processWebhook(corsair, FORM, mailchimpForm, {
			secret: SECRET,
		});
		expect([result.plugin, result.action]).toEqual(['mailchimp', 'subscribe']);
		expect(verified).toHaveBeenCalledTimes(1);
	});

	it('R3a twilio only: routed to twilio', async () => {
		const corsair = createCorsair({
			plugins: [twilioPlugin(() => undefined)],
			kek: KEK,
		});
		const result = await processWebhook(corsair, twilioHeaders(), twilioForm);
		expect([result.plugin, result.action]).toEqual([
			'twilio',
			'message.statusUpdate',
		]);
	});

	it('R3b twilio only: a correctly signed delivery passes verification', async () => {
		const verified = jest.fn();
		const corsair = createCorsair({
			plugins: [twilioPlugin(verified)],
			kek: KEK,
		});
		await processWebhook(corsair, twilioHeaders(), twilioForm);
		expect(verified).toHaveBeenCalledTimes(1);
	});

	it('R4a twilio + posthog: routed to twilio', async () => {
		const corsair = createCorsair({
			plugins: [posthog(), twilioPlugin(() => undefined)],
			kek: KEK,
		});
		const result = await processWebhook(corsair, twilioHeaders(), twilioForm);
		expect(result.plugin).toBe('twilio');
	});

	it('R4b twilio + telegram: routed to twilio', async () => {
		const corsair = createCorsair({
			plugins: [telegram(), twilioPlugin(() => undefined)],
			kek: KEK,
		});
		const result = await processWebhook(corsair, twilioHeaders(), twilioForm);
		expect(result.plugin).toBe('twilio');
	});

	it('R5a mailchimp + posthog, delivery without ?secret=: no match, no throw', async () => {
		const corsair = createCorsair({
			plugins: [mailchimpPlugin(() => undefined), posthog()],
			kek: KEK,
		});
		const result = await processWebhook(corsair, FORM, mailchimpForm);
		expect(result.plugin).toBeNull();
	});

	it('R5b mailchimp + telegram, delivery without ?secret=: no match, no throw', async () => {
		const corsair = createCorsair({
			plugins: [mailchimpPlugin(() => undefined), telegram()],
			kek: KEK,
		});
		const result = await processWebhook(corsair, FORM, mailchimpForm);
		expect(result.plugin).toBeNull();
	});

	it('R6 mailchimp + posthog + telegram, valid delivery: mailchimp is reached first', async () => {
		const verified = jest.fn();
		const corsair = createCorsair({
			plugins: [mailchimpPlugin(verified), posthog(), telegram()],
			kek: KEK,
		});
		const result = await processWebhook(corsair, FORM, mailchimpForm, {
			secret: SECRET,
		});
		expect(result.plugin).toBe('mailchimp');
		expect(verified).toHaveBeenCalledTimes(1);
	});
});
