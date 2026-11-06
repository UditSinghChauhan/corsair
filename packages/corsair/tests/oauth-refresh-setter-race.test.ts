// Does the refresh lock keep a rotated
// refresh_token safe from a second key manager? Every row asserts the SAFE outcome,
// so a red row is the finding. Modelled on tests/oauth-refresh-lock.test.ts.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
// @ts-expect-error - better-sqlite3 types may not be available
import Database from 'better-sqlite3';
import type {
	KyselyPlugin,
	PluginTransformQueryArgs,
	PluginTransformResultArgs,
	QueryId,
	QueryResult,
	RootOperationNode,
	UnknownRow,
} from 'kysely';
import { SelectQueryNode, TableNode, UpdateQueryNode } from 'kysely';
import postgres from 'postgres';
import {
	encryptConfig,
	encryptDEK,
	generateDEK,
} from '../core/auth/encryption';
import { createAccountKeyManager } from '../core/auth/key-manager';
import type { OAuthAccessContext } from '../core/auth/oauth-access';
import { getOAuthAccessToken } from '../core/auth/oauth-access';
import type { CorsairDatabase } from '../db/kysely/database';
import { createCorsairDatabase } from '../db/kysely/database';
import type { HubConfig } from '../hub/types';

const KEK = 'test-kek-with-at-least-32-characters!!';
// Own schema and tenant: jest runs this file beside oauth-refresh-lock.test.ts on
// the same database, and the advisory lock key is derived from tenant + integration.
const SCHEMA = 'corsair_refresh_setter_race_test';
const TENANT = 'setter-race';
const LOCK_KEY = `corsair-refresh:${TENANT}:github`;
const PG_URL = process.env.DATABASE_URL ?? '';
const TEST_TIMEOUT_MS = 15_000;
const hub: HubConfig = {
	apiUrl: 'https://hub.test',
	projectApiKey: 'ck_prod_test',
	signingSecret: 'sec',
};
const localIntegration = { client_id: 'cid', client_secret: 'sec' };
const staleAccount = {
	access_token: 'stale',
	expires_at: '1',
	refresh_token: 'rt-0',
};

const PG_DDL = `
CREATE TABLE ${SCHEMA}.corsair_integrations (
  id TEXT PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), name TEXT NOT NULL,
  config JSONB NOT NULL DEFAULT '{}', dek TEXT NULL);
CREATE TABLE ${SCHEMA}.corsair_accounts (
  id TEXT PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), tenant_id TEXT NOT NULL,
  integration_id TEXT NOT NULL, config JSONB NOT NULL DEFAULT '{}', dek TEXT NULL);
`;

const SQLITE_DDL = `
CREATE TABLE IF NOT EXISTS corsair_integrations (
  id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  name TEXT NOT NULL, config TEXT NOT NULL, dek TEXT NULL);
CREATE TABLE IF NOT EXISTS corsair_accounts (
  id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  tenant_id TEXT NOT NULL, integration_id TEXT NOT NULL, config TEXT NOT NULL, dek TEXT NULL);
`;

const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function latch(): { promise: Promise<void>; open: () => void } {
	let open: () => void = () => {};
	const promise = new Promise<void>((resolve) => {
		open = resolve;
	});
	return { promise, open };
}

// Holds the first corsair_accounts SELECT after arm() until release(), so a setter
// can be parked between the read and the write of its read-merge-write.
function accountReadGate() {
	const selects = new WeakSet<QueryId>();
	const reached = latch();
	const released = latch();
	let armed = false;
	const plugin: KyselyPlugin = {
		transformQuery(args: PluginTransformQueryArgs): RootOperationNode {
			const { node } = args;
			if (
				SelectQueryNode.is(node) &&
				node.from?.froms.some(
					(f) =>
						TableNode.is(f) && f.table.identifier.name === 'corsair_accounts',
				)
			) {
				selects.add(args.queryId);
			}
			return node;
		},
		async transformResult(
			args: PluginTransformResultArgs,
		): Promise<QueryResult<UnknownRow>> {
			if (armed && selects.has(args.queryId)) {
				armed = false;
				reached.open();
				await released.promise;
			}
			return args.result;
		},
	};
	return {
		plugin,
		arm: () => {
			armed = true;
		},
		reached: reached.promise,
		release: released.open,
	};
}

// Holds the first corsair_accounts UPDATE after arm() until release(), AFTER it has
// run: inside #2010's locked refresh that leaves A with an uncommitted write (and
// the row lock) while another connection reads the last committed row.
function accountWriteGate() {
	const updates = new WeakSet<QueryId>();
	const reached = latch();
	const released = latch();
	let armed = false;
	const plugin: KyselyPlugin = {
		transformQuery(args: PluginTransformQueryArgs): RootOperationNode {
			const { node } = args;
			if (
				UpdateQueryNode.is(node) &&
				TableNode.is(node.table) &&
				node.table.table.identifier.name === 'corsair_accounts'
			) {
				updates.add(args.queryId);
			}
			return node;
		},
		async transformResult(
			args: PluginTransformResultArgs,
		): Promise<QueryResult<UnknownRow>> {
			if (armed && updates.has(args.queryId)) {
				armed = false;
				reached.open();
				await released.promise;
			}
			return args.result;
		},
	};
	return {
		plugin,
		arm: () => {
			armed = true;
		},
		reached: reached.promise,
		release: released.open,
	};
}

const tokenResponse = (body: Record<string, string | number>, status = 200) =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json' },
	});

// Fake provider/hub: rotates the refresh token on every use and rejects a reused
// one, like GitHub user-to-server tokens. `hold` parks the request mid-provider-call.
function installRotatingEndpoint(
	initialRefresh: string,
	hold?: { reached: () => void; released: Promise<void> },
) {
	let current = initialRefresh;
	let n = 0;
	const state = { requests: 0, sent: [] as string[] };
	const endpoint: typeof fetch = async (_input, init) => {
		state.requests += 1;
		const raw = String(init?.body);
		const parsed: { refresh_token?: string } = raw.startsWith('{')
			? JSON.parse(raw)
			: { refresh_token: new URLSearchParams(raw).get('refresh_token') ?? '' };
		const sent = parsed.refresh_token ?? '';
		state.sent.push(sent);
		if (hold) {
			hold.reached();
			await hold.released;
		}
		await wait(50);
		if (sent !== current) {
			return tokenResponse({ error: 'bad_refresh_token' }, 400);
		}
		n += 1;
		current = `rt-${n}`;
		return tokenResponse({
			access_token: `at-${n}`,
			refresh_token: current,
			expires_in: 3600,
		});
	};
	global.fetch = endpoint;
	return state;
}

async function seed(
	database: CorsairDatabase,
	integrationConfig: Record<string, string>,
	accountConfig: Record<string, string>,
) {
	const now = new Date();
	const dek = generateDEK();
	const encryptedDek = await encryptDEK(dek, KEK);
	await database.db
		.insertInto('corsair_integrations')
		.values({
			id: 'integration-github',
			created_at: now,
			updated_at: now,
			name: 'github',
			config: encryptConfig(integrationConfig, dek),
			dek: encryptedDek,
		})
		.execute();
	await database.db
		.insertInto('corsair_accounts')
		.values({
			id: 'account-setter-race',
			created_at: now,
			updated_at: now,
			tenant_id: TENANT,
			integration_id: 'integration-github',
			config: encryptConfig(accountConfig, dek),
			dek: encryptedDek,
		})
		.execute();
}

const makeKeys = (database: CorsairDatabase) =>
	createAccountKeyManager({
		authType: 'oauth_2',
		integrationName: 'github',
		tenantId: TENANT,
		kek: KEK,
		database,
	});

// getOAuthAccessToken assigns _refreshAuth on the context for the 401 retry path.
type RefreshContext = OAuthAccessContext & {
	_refreshAuth?: () => Promise<string>;
};

const makeContext = (database: CorsairDatabase): RefreshContext => ({
	keys: makeKeys(database),
	hub,
	tenantId: TENANT,
});

const opts = { plugin: 'github', tokenUrl: 'https://github.test/token' };

const forcedRefresh = (ctx: RefreshContext): Promise<string> => {
	if (!ctx._refreshAuth) {
		throw new Error('getOAuthAccessToken did not set _refreshAuth');
	}
	return ctx._refreshAuth();
};

async function readStored(database: CorsairDatabase) {
	const keys = makeKeys(database);
	return {
		access_token: await keys.get_access_token(),
		refresh_token: await keys.get_refresh_token(),
		scope: await keys.get_scope(),
	};
}

// The next caller's refresh on a fresh manager. A rolled-back row makes the plain
// call refresh with the spent token; a safe row needs the forced path to refresh.
async function nextRefresh(database: CorsairDatabase): Promise<string> {
	const ctx = makeContext(database);
	try {
		await getOAuthAccessToken(ctx, opts);
		return await forcedRefresh(ctx);
	} catch (err) {
		// err is unknown because anything can be thrown; narrowed here for the report.
		return `threw: ${err instanceof Error ? err.message : String(err)}`;
	}
}

// Raw values per row: a green row has no jest diff to read them from.
const report = (row: string, got: object) => {
	console.log(`[setter-race] ${row} ${JSON.stringify(got)}`);
};

// The T2 race: B reads the row, A refreshes and commits, then B writes its snapshot.
async function setterStraddlesRefresh(
	row: string,
	database: CorsairDatabase,
	databaseB: CorsairDatabase,
	gate: ReturnType<typeof accountReadGate>,
) {
	const state = installRotatingEndpoint('rt-0');
	const ctxA = makeContext(database);
	const keysB = makeKeys(databaseB);
	try {
		gate.arm();
		const setter = keysB.set_scope('read,write');
		await gate.reached;
		const tokenA = await getOAuthAccessToken(ctxA, opts);
		const afterRefresh = await readStored(database);
		gate.release();
		await setter;
		const stored = await readStored(database);
		const next = await nextRefresh(database);
		report(row, {
			tokenA,
			afterRefresh,
			stored,
			next,
			requests: state.requests,
			sent: state.sent,
		});
		expect({ tokenA, stored, next }).toEqual({
			tokenA: 'at-1',
			stored: {
				access_token: 'at-1',
				refresh_token: 'rt-1',
				scope: 'read,write',
			},
			next: 'at-2',
		});
	} finally {
		gate.release();
	}
}

describe('refresh lock vs a second key manager', () => {
	const realFetch = global.fetch;
	afterEach(() => {
		global.fetch = realFetch;
	});

	const truthy = (v?: string) => ['1', 'true', 'yes'].includes(v ?? '');
	const local =
		/^postgres(ql)?:\/\/([^@/]*@)?(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/;
	const pgEnabled =
		truthy(process.env.RUN_PG_TESTS) &&
		!truthy(process.env.SKIP_PG_TESTS) &&
		local.test(PG_URL);
	const pgIt = pgEnabled ? it : it.skip;

	let admin: postgres.Sql;
	let sql: postgres.Sql;
	beforeAll(async () => {
		if (!pgEnabled) return;
		admin = postgres(PG_URL, { max: 1 });
		await admin.unsafe(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
		await admin.unsafe(`CREATE SCHEMA ${SCHEMA}`);
		await admin.unsafe(PG_DDL);
		sql = postgres(PG_URL, { max: 10, connection: { search_path: SCHEMA } });
	});
	afterAll(async () => {
		if (!pgEnabled) return;
		await sql.end({ timeout: 2 });
		await admin.unsafe(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
		await admin.end({ timeout: 2 });
	});
	beforeEach(async () => {
		if (!pgEnabled) return;
		await sql.unsafe(
			`TRUNCATE ${SCHEMA}.corsair_accounts, ${SCHEMA}.corsair_integrations`,
		);
	});

	pgIt(
		'P0 control: two key managers, one refresh, both get at-1',
		async () => {
			const database = createCorsairDatabase(sql);
			await seed(database, localIntegration, staleAccount);
			const state = installRotatingEndpoint('rt-0');
			const [a, b] = await Promise.all([
				getOAuthAccessToken(makeContext(database), opts),
				getOAuthAccessToken(makeContext(database), opts),
			]);
			const stored = await readStored(database);
			report('P0', {
				a,
				b,
				stored,
				requests: state.requests,
				sent: state.sent,
			});
			expect([a, b]).toEqual(['at-1', 'at-1']);
			expect(state.requests).toBe(1);
			expect(stored.refresh_token).toBe('rt-1');
		},
		TEST_TIMEOUT_MS,
	);

	pgIt(
		'P1: a setter that read before a locked refresh commits keeps rt-1 and the next refresh works',
		async () => {
			const database = createCorsairDatabase(sql);
			await seed(database, localIntegration, staleAccount);
			const gate = accountReadGate();
			await setterStraddlesRefresh(
				'P1',
				database,
				{ ...database, db: database.db.withPlugin(gate.plugin) },
				gate,
			);
		},
		TEST_TIMEOUT_MS,
	);

	pgIt(
		'P2: a setter during the advisory lock, mid-provider-call, keeps rt-1',
		async () => {
			const database = createCorsairDatabase(sql);
			await seed(database, localIntegration, staleAccount);
			const reached = latch();
			const released = latch();
			const state = installRotatingEndpoint('rt-0', {
				reached: reached.open,
				released: released.promise,
			});
			try {
				const call = getOAuthAccessToken(makeContext(database), opts);
				await reached.promise;
				const [probe] = await sql.begin(
					(tx) =>
						tx`select pg_try_advisory_xact_lock(hashtext(${LOCK_KEY}::text)) as free`,
				);
				const setter = makeKeys(database).set_scope('read,write');
				const setterDuringLock = await Promise.race([
					setter.then(() => 'completed'),
					wait(1500).then(() => 'blocked'),
				]);
				released.open();
				const tokenA = await call;
				await setter;
				const stored = await readStored(database);
				report('P2', {
					lockHeldByA: probe?.free === false,
					setterDuringLock,
					tokenA,
					stored,
					requests: state.requests,
					sent: state.sent,
				});
				expect(probe?.free).toBe(false);
				expect({ tokenA, stored }).toEqual({
					tokenA: 'at-1',
					stored: {
						access_token: 'at-1',
						refresh_token: 'rt-1',
						scope: 'read,write',
					},
				});
			} finally {
				released.open();
			}
		},
		TEST_TIMEOUT_MS,
	);

	pgIt(
		'P2b: a setter that reads while the locked refresh has written but not committed keeps rt-1',
		async () => {
			const database = createCorsairDatabase(sql);
			await seed(database, localIntegration, staleAccount);
			const state = installRotatingEndpoint('rt-0');
			const gate = accountWriteGate();
			const databaseA = {
				...database,
				db: database.db.withPlugin(gate.plugin),
			};
			try {
				gate.arm();
				const call = getOAuthAccessToken(makeContext(databaseA), opts);
				await gate.reached;
				// A holds the advisory lock and an uncommitted UPDATE on the row.
				const [probe] = await sql.begin(
					(tx) =>
						tx`select pg_try_advisory_xact_lock(hashtext(${LOCK_KEY}::text)) as free`,
				);
				const setter = makeKeys(database).set_scope('read,write');
				const setterWhileUncommitted = await Promise.race([
					setter.then(() => 'completed'),
					wait(1000).then(() => 'blocked'),
				]);
				gate.release();
				const tokenA = await call;
				await setter;
				const stored = await readStored(database);
				const next = await nextRefresh(database);
				report('P2b', {
					lockHeldByA: probe?.free === false,
					setterWhileUncommitted,
					tokenA,
					stored,
					next,
					requests: state.requests,
					sent: state.sent,
				});
				expect({ tokenA, stored, next }).toEqual({
					tokenA: 'at-1',
					stored: {
						access_token: 'at-1',
						refresh_token: 'rt-1',
						scope: 'read,write',
					},
					next: 'at-2',
				});
			} finally {
				gate.release();
			}
		},
		TEST_TIMEOUT_MS,
	);

	for (const [label, integration] of [
		['local path', localIntegration],
		['hub path', {}],
	] as const) {
		pgIt(
			`P3 (${label}): two forced refreshes, one token request, same new token`,
			async () => {
				const database = createCorsairDatabase(sql);
				await seed(database, integration, {
					access_token: 'at-0',
					expires_at: String(Math.floor(Date.now() / 1000) + 3600),
					refresh_token: 'rt-0',
				});
				const state = installRotatingEndpoint('rt-0');
				const ctxA = makeContext(database);
				const ctxB = makeContext(database);
				// Both tokens look fresh, so this only sets _refreshAuth: no request.
				expect(await getOAuthAccessToken(ctxA, opts)).toBe('at-0');
				expect(await getOAuthAccessToken(ctxB, opts)).toBe('at-0');
				expect(state.requests).toBe(0);
				const [a, b] = await Promise.all([
					forcedRefresh(ctxA),
					forcedRefresh(ctxB),
				]);
				const stored = await readStored(database);
				report(`P3 ${label}`, {
					a,
					b,
					stored,
					requests: state.requests,
					sent: state.sent,
				});
				expect([a, b]).toEqual(['at-1', 'at-1']);
				expect(state.requests).toBe(1);
				expect(stored.refresh_token).toBe('rt-1');
			},
			TEST_TIMEOUT_MS,
		);
	}

	it(
		'P4 control on SQLite: P1, no lock by design',
		async () => {
			// Two connections on one WAL file: a parked read holds its own connection.
			const dir = mkdtempSync(join(tmpdir(), 'setter-race-'));
			const open = () => {
				const sqlite = new Database(join(dir, 'p4.db'));
				sqlite.pragma('journal_mode = WAL');
				sqlite.pragma('busy_timeout = 5000');
				sqlite.exec(SQLITE_DDL);
				return createCorsairDatabase(sqlite);
			};
			const database = open();
			const second = open();
			try {
				await seed(database, localIntegration, staleAccount);
				const gate = accountReadGate();
				await setterStraddlesRefresh(
					'P4',
					database,
					{ ...second, db: second.db.withPlugin(gate.plugin) },
					gate,
				);
			} finally {
				await database.db.destroy();
				await second.db.destroy();
				rmSync(dir, { recursive: true, force: true });
			}
		},
		TEST_TIMEOUT_MS,
	);
});
