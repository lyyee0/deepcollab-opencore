import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createPrivateKey } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertLocalPath } from '../src/local-paths.mjs';
import { ToolGateway, demoAdapters } from '../src/gateway.mjs';
import { generateAuditKey, publicKeyFromSpki, sha256Hex, signPayload, verifyEventChain } from '../src/audit-chain.mjs';
import { parseTimestampResponse, verifyTimestampToken } from '../src/timestamp.mjs';
import { verifyTrustPackage } from '../tools/verify.mjs';
import { verifyStreamFile } from '../tools/verify-stream.mjs';

const ROOT = dirname(fileURLToPath(import.meta.url));
const sampleStream = join(ROOT, '..', 'examples', 'demo-event-stream.jsonl');
const temporaryDirectories = new Set();

async function tempDir(prefix = 'deepcollab-regression-') {
  const path = await mkdtemp(join(tmpdir(), prefix));
  temporaryDirectories.add(path);
  return path;
}

test.after(async () => {
  await Promise.all([...temporaryDirectories].map(path => rm(path, { recursive: true, force: true })));
});

test('P0-1 verify-stream-file-missing fails closed', async () => {
  const root = await tempDir();
  const result = await verifyEventChain(join(root, 'missing.jsonl'));
  assert.equal(result.ok, false);
  assert.ok(result.problems.some(problem => problem.code === 'AUDIT_CHAIN_FILE_MISSING'));
});

test('P0-1 verify-stream CLI reports AUDIT_STREAM_MISSING and exits 1 for a missing file', async () => {
  const root = await tempDir();
  const missing = join(root, 'missing.jsonl');
  const result = spawnSync(process.execPath, [join(ROOT, '..', 'tools', 'verify-stream.mjs'), missing], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /AUDIT_STREAM_MISSING/);
});

test('P0-2 valid chain plus trailing garbage is rejected', async () => {
  const root = await tempDir();
  const file = join(root, 'events.jsonl');
  await writeFile(file, await readFile(sampleStream, 'utf8') + 'this is not json\n');
  const result = await verifyEventChain(file);
  assert.equal(result.ok, false);
  assert.ok(result.problems.some(problem => problem.code === 'AUDIT_CHAIN_BROKEN_LINE'));
});

test('P0-2 valid chain plus trailing unchained JSON, including fake chain fields, is rejected', async () => {
  const root = await tempDir();
  const file = join(root, 'events.jsonl');
  const base = await readFile(sampleStream, 'utf8');
  const fake = JSON.stringify({ seq: 11, type: 'tool.action_completed', prevHash: 'deadbeef', hash: 'cafebabe' });
  await writeFile(file, base + fake + '\n');
  const result = await verifyEventChain(file);
  assert.equal(result.ok, false);
  assert.ok(result.problems.some(problem => problem.code === 'AUDIT_UNCHAINED_SUFFIX'));
});

test('P0-3 package signing key pin is checked against a keyId recomputed from SPKI', async () => {
  const root = await tempDir();
  const key = generateAuditKey();
  const declaredId = 'ed25519:1111111111111111';
  const core = { signingKeys: [{ keyId: declaredId, publicKeySpki: key.publicKey }], checkpoints: [] };
  const bundle = {
    ...core,
    signature: { keyId: declaredId, value: signPayload(createPrivateKey(key.privateKeyPem), core) },
  };
  await mkdir(root, { recursive: true });
  await writeFile(join(root, 'SHA256SUMS.txt'), '');
  await writeFile(join(root, 'trust-bundle.json'), JSON.stringify(bundle));
  const result = await verifyTrustPackage(root, { expectSigningKey: declaredId });
  const mismatch = result.checks.find(check => check.code === 'SIGNING_KEY_ID_MISMATCH');
  assert.ok(mismatch);
  assert.equal(mismatch.detail.declaredId, declaredId);
  assert.equal(mismatch.detail.recomputedId, publicKeyFromSpki(key.publicKey).keyId);
  assert.ok(result.checks.some(check => check.code === 'SIGNING_KEY_MISMATCH' && check.status === 'fail'));
  assert.equal(result.ok, false);
});

test('P0-4 trust package reports HEAD_MISMATCH when headHash differs', async () => {
  const root = await tempDir();
  const eventBytes = await readFile(sampleStream);
  const lines = eventBytes.toString('utf8').trimEnd().split(/\r?\n/);
  const finalEvent = JSON.parse(lines.at(-1));
  const actualHash = finalEvent.chain?.hash || finalEvent.meta?.chain?.hash;
  const actualSeq = finalEvent.chain?.seq || finalEvent.meta?.chain?.seq;
  await writeFile(join(root, 'events.jsonl'), eventBytes);
  await writeFile(join(root, 'SHA256SUMS.txt'), `${sha256Hex(eventBytes)}  events.jsonl\n`);
  await writeFile(join(root, 'trust-bundle.json'), JSON.stringify({
    scope: {
      headSeq: actualSeq,
      headHash: '0'.repeat(64),
      evidence: { included: true, path: 'events.jsonl', sha256: sha256Hex(eventBytes) },
    },
    signingKeys: [], checkpoints: [],
  }));
  assert.notEqual(actualHash, '0'.repeat(64));
  const result = await verifyTrustPackage(root);
  assert.ok(result.checks.some(check => check.code === 'HEAD_MISMATCH' && check.status === 'fail'));
});

test('P0-5 audit hook payload is sanitized before the event is persisted', async () => {
  const persisted = [];
  const gateway = new ToolGateway({ store: { append: async event => persisted.push(event) } });
  gateway.register({
    name: 'audit_echo',
    validate: args => args,
    audit: () => ({ x_api_key: 'secret-api-value', cookie: 'secret-cookie-value', private_key: 'secret-private-value' }),
    execute: async () => ({ ok: true }),
  });
  await gateway.execute({ tool: 'audit_echo', arguments: {} }, { sessionId: 's1', runId: 'r1' });
  const requested = persisted.find(event => event.type === 'tool.action_requested');
  assert.deepEqual(requested.payload.arguments, {
    x_api_key: '[REDACTED]', cookie: '[REDACTED]', private_key: '[REDACTED]',
  });
});

test('P0-6 timestamp verification requires an independently supplied expected imprint', async () => {
  const response = await readFile(join(ROOT, 'fixtures', 'tsa-response.tsr'));
  const token = parseTimestampResponse(response).token;
  const missingPin = verifyTimestampToken(token);
  assert.equal(missingPin.ok, false);
  assert.equal(missingPin.verified.expectedImprint, false);
  assert.equal(verifyTimestampToken(token, { expectedImprint: createHash('sha256').update('deepcollab-checkpoint').digest('hex') }).ok, true);
});

test('P1-7 verify-stream accepts keyId and base64 SPKI pins without undefined diagnostics', async () => {
  const stream = await readFile(sampleStream, 'utf8');
  const checkpoint = stream.trimEnd().split(/\r?\n/).map(line => JSON.parse(line)).at(-1);
  const payload = checkpoint.payload || {};
  const publicKey = payload.public_key || payload.publicKeySpki;
  const keyId = payload.checkpoint?.key_id || payload.checkpoint?.keyId;
  const derived = publicKeyFromSpki(publicKey);
  assert.equal(keyId, derived.keyId);
  assert.equal((await verifyStreamFile(sampleStream, keyId)).ok, true);
  assert.equal((await verifyStreamFile(sampleStream, publicKey)).ok, true);
  const wrong = await verifyStreamFile(sampleStream, 'ed25519:0000000000000000');
  assert.equal(wrong.ok, false);
  assert.doesNotMatch(wrong.problems.map(problem => problem.message).join('\n'), /undefined/);
});

test('P1-8 trust package paths reject ../ traversal and escaped sums entries', async () => {
  const root = await tempDir();
  const parent = dirname(root);
  await writeFile(join(parent, `outside-${root.split(/[/\\]/).at(-1)}.txt`), 'outside');
  assert.throws(() => assertLocalPath(resolve(root, '..', 'outside.txt'), root), error => error.code === 'REMOTE_PATH_DENIED');
  await writeFile(join(root, 'SHA256SUMS.txt'), `${'0'.repeat(64)}  ../outside.txt\n`);
  await writeFile(join(root, 'trust-bundle.json'), JSON.stringify({ signingKeys: [], checkpoints: [] }));
  const result = await verifyTrustPackage(root);
  assert.ok(result.checks.some(check => check.code === 'PACKAGE_PATH_DENIED' && check.status === 'fail'));
});

test('P1-8 trust package paths reject an external symlink or junction target', { skip: process.platform === 'win32' ? 'covered by the junction regression on Windows' : false }, async () => {
  const root = await tempDir();
  const outside = await tempDir('deepcollab-outside-');
  await mkdir(join(root, 'linked'), { recursive: true });
  await writeFile(join(outside, 'outside.txt'), 'outside');
  await symlink(outside, join(root, 'linked', 'escape'), 'dir');
  assert.throws(
    () => assertLocalPath(join(root, 'linked', 'escape', 'outside.txt'), root),
    error => error.code === 'REMOTE_PATH_DENIED',
  );
});

test('P1-8 trust package paths reject an external Windows junction target', { skip: process.platform !== 'win32' }, async () => {
  const root = await tempDir();
  const outside = await tempDir('deepcollab-outside-');
  await mkdir(join(root, 'linked'), { recursive: true });
  await writeFile(join(outside, 'outside.txt'), 'outside');
  await symlink(outside, join(root, 'linked', 'escape'), 'junction');
  assert.throws(
    () => assertLocalPath(join(root, 'linked', 'escape', 'outside.txt'), root),
    error => error.code === 'REMOTE_PATH_DENIED',
  );
});

async function demoGatewayAt(root) {
  const events = [];
  const gateway = new ToolGateway({ store: { append: async event => events.push(event) } });
  for (const adapter of demoAdapters({ demoRoot: root })) gateway.register(adapter);
  return { gateway, events };
}

test('P1-9 demo blocks ../ traversal', async () => {
  const base = await tempDir();
  const root = join(base, 'demo');
  const { gateway } = await demoGatewayAt(root);
  await assert.rejects(
    gateway.execute({ tool: 'demo_read_file', arguments: { path: '../outside.txt' } }, { sessionId: 's1', runId: 'r1', roleId: 'observer' }),
    error => error.code === 'DEMO_PATH_DENIED',
  );
});

async function rejectsDemoLinkEscape(linkType) {
  const base = await tempDir();
  const root = join(base, 'demo');
  const outside = join(base, 'outside');
  await mkdir(root, { recursive: true });
  await mkdir(outside, { recursive: true });
  await writeFile(join(outside, 'secret.txt'), 'outside-root');
  const link = join(root, 'escape');
  await symlink(outside, link, linkType);
  const { gateway } = await demoGatewayAt(root);
  await assert.rejects(
    gateway.execute({ tool: 'demo_read_file', arguments: { path: 'escape/secret.txt' } }, { sessionId: 's1', runId: 'r1', roleId: 'observer' }),
    error => error.code === 'DEMO_PATH_DENIED',
  );
}

test('P1-9 demo rejects an escaping directory symlink', { skip: process.platform === 'win32' }, async () => {
  await rejectsDemoLinkEscape('dir');
});

test('P1-9 demo rejects an escaping Windows junction', { skip: process.platform !== 'win32' }, async () => {
  await rejectsDemoLinkEscape('junction');
});
