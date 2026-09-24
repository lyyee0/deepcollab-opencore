import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { mkdir, open, readFile, stat, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';
import { canonicalJson } from './canonical.mjs';
import { chainOf, normalizeLegacyEvent } from './event-codec.mjs';
import { DEFAULT_TSA_URL, requestTimestamp, verifyTimestampToken } from './timestamp.mjs';

// chainOf 的既有导入路径保持不变（它描述磁盘编码，归 event-codec 所有）。
export { chainOf };

// 审计事件链与签名检查点。
//
// 这一层要回答三个问题，且答案必须是可独立验证的：
//   1. 这条记录有没有被改过？   → 事件级前序哈希链（seq + prev + hash）
//   2. 改过之后能不能被发现？   → 每个链式事件都被后续事件的 prev 引用，改一条就断链
//   3. 是谁、在什么时候确认的？ → Ed25519 签名检查点（覆盖链头 + 前序检查点哈希）
//
// 明确不做的事：不改写历史行（用"创世锚点"把已有内容一次性封进链），不隐式联网取时间戳，
// 不把私钥写进事件流。私钥来源单一：环境变量 DEEPCOLLAB_AUDIT_KEY（值可以是 PEM 原文、
// base64/hex 的 PKCS#8 DER，或指向密钥文件的路径）。

export const CHAIN_ALGORITHM = 'sha256';
export const SIGNATURE_ALGORITHM = 'ed25519';
export const GENESIS = 'genesis';
export const DEFAULT_KEY_ENV = 'DEEPCOLLAB_AUDIT_KEY';
export const CHECKPOINT_TYPE = 'audit.checkpoint';
const TAIL_BYTES = 512 * 1024;
const MAX_VERIFY_BYTES = 256 * 1024 * 1024;

export function chainError(code, message) {
  return Object.assign(new Error(message), { code, exitCode: 2 });
}

export const sha256Hex = value => createHash('sha256').update(value).digest('hex');

// 编码层自己写入的 meta 键不参与哈希：它们只在磁盘往返时出现，写盘前并不存在。
// 不排除它们，shared-v1 事件读回来 meta 就变了，链会整体误报断裂。
const SCHEMA_META_KEYS = new Set(['internal_schema', 'importedFromSchema', 'imported_chain', 'chain']);

export function stableMeta(meta) {
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return {};
  const out = {};
  for (const key of Object.keys(meta).sort()) {
    if (SCHEMA_META_KEYS.has(key)) continue;
    out[key] = meta[key];
  }
  return out;
}

// 被哈希的字段集合：链字段（seq/prev/genesis）参与，chain.hash 与 algorithm 不参与。
export function eventHashInput(event, chain) {
  return {
    schemaVersion: event.schemaVersion ?? null,
    id: event.id,
    timestamp: event.timestamp,
    runId: event.runId ?? null,
    sessionId: event.sessionId ?? null,
    source: event.source ?? null,
    type: event.type,
    payload: event.payload ?? {},
    meta: stableMeta(event.meta),
    seq: chain.seq,
    prev: chain.prev,
    genesis: chain.genesis ?? null,
  };
}

export function computeEventHash(event, chain) {
  return sha256Hex(canonicalJson(eventHashInput(event, chain)));
}

async function readTail(path, length, size) {
  const handle = await open(path, 'r');
  try {
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, size - length);
    return buffer;
  } finally {
    await handle.close();
  }
}

// 全文件锚点：把"建立链之前就已经存在的内容"一次性封进 sha256。
// 历史行不改写，但从此以后它们也不能被改动而不被发现。
export async function legacyAnchor(path) {
  const text = await readFile(path, 'utf8');
  const lines = text.split(/\r?\n/).filter(line => line.trim());
  return { events: lines.length, bytes: Buffer.byteLength(text, 'utf8'), sha256: sha256Hex(text) };
}

// 读取当前链头。只在锁内调用。
//  - 最后一条非空行必须携带链信息，否则拒绝追加（fail closed），避免把断裂的流续上。
//  - 尾部没有任何链信息时才可能是"尚未建链的历史流"，此时读全文确认，并返回创世锚点。
export async function readChainHead(path) {
  const info = await stat(path).catch(() => null);
  if (!info || info.size === 0) return { seq: 0, hash: GENESIS, anchor: null, empty: true };
  const tailLength = Math.min(info.size, TAIL_BYTES);
  const tail = (await readTail(path, tailLength, info.size)).toString('utf8');
  const tailLines = tail.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const lastLine = tailLines[tailLines.length - 1];
  let last = null;
  try { last = JSON.parse(lastLine); }
  catch { throw chainError('AUDIT_CHAIN_TAIL_INVALID', '事件流最后一行不是完整 JSON（可能是写入中断）；拒绝追加新事件，请先运行 dcc audit check'); }
  const chain = chainOf(last);
  if (chain && Number.isSafeInteger(Number(chain.seq)) && typeof chain.hash === 'string') {
    return { seq: Number(chain.seq), hash: chain.hash, anchor: null };
  }
  // 最后一条非空行不在链上：必须区分两种情况，否则会把断裂的流当成"新历史流"再接一条新链。
  //   1) 文件里存在链式事件 → 链已断裂，拒绝追加（fail closed）
  //   2) 文件里完全没有链式事件 → 纯历史流，建立创世锚点，从这里开始成链
  const full = tailLength >= info.size ? tail : await readFile(path, 'utf8');
  const lines = full.split(/\r?\n/).filter(line => line.trim());
  let chained = 0;
  for (const line of lines) {
    try { if (chainOf(JSON.parse(line))) chained++; } catch { /* 坏行由 audit check 负责判定 */ }
  }
  if (chained > 0) {
    throw chainError('AUDIT_CHAIN_BROKEN', '事件流中存在链式事件，但最后一条不在链上；拒绝追加新事件，请先运行 dcc audit verify 定位断点');
  }
  return { seq: 0, hash: GENESIS, legacy: true, empty: false,
    anchor: { events: lines.length, bytes: Buffer.byteLength(full, 'utf8'), sha256: sha256Hex(full) } };
}

// 给一批新事件接上链。纯函数式：只依赖传入的 head 与事件本身。
export function chainEvents(events, head = { seq: 0, hash: GENESIS, anchor: null }) {
  const out = [];
  let seq = head.seq;
  let prev = head.hash;
  let anchor = head.anchor || null;
  for (const event of events) {
    seq += 1;
    const chain = { seq, prev, algorithm: CHAIN_ALGORITHM };
    if (anchor) chain.genesis = anchor;
    chain.hash = computeEventHash(event, chain);
    out.push({ ...event, chain });
    prev = chain.hash;
    anchor = null;
  }
  return out;
}

// —— 密钥 ————————————————————————————————————————————————

function decodePrivateKey(material) {
  const buffer = Buffer.isBuffer(material) ? material : Buffer.from(String(material), 'utf8');
  const text = buffer.toString('utf8');
  if (text.includes('BEGIN')) return createPrivateKey({ key: text, format: 'pem' });
  const compact = text.replace(/\s+/g, '');
  const attempts = [];
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0) attempts.push(Buffer.from(compact, 'hex'));
  attempts.push(Buffer.from(compact, 'base64'));
  let last = null;
  for (const der of attempts) {
    try { return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }); } catch (error) { last = error; }
  }
  throw new Error('无法解析 Ed25519 私钥（支持 PEM、PKCS#8 DER 的 base64/hex，或密钥文件路径）: ' + (last?.message || ''));
}

export function resolveAuditKey(environment = process.env, { keyEnv = DEFAULT_KEY_ENV } = {}) {
  const raw = environment?.[keyEnv];
  if (raw === undefined || raw === null || !String(raw).trim()) return { available: false, reason: 'AUDIT_KEY_UNSET', keyEnv };
  const value = String(raw).trim();
  let material = value;
  let origin = 'env-value';
  try {
    if (existsSync(value)) { material = readFileSync(value); origin = 'env-path'; }
  } catch { /* 保持 env-value */ }
  let privateKey;
  try { privateKey = decodePrivateKey(material); }
  catch (error) { return { available: false, reason: 'AUDIT_KEY_INVALID', keyEnv, message: error.message }; }
  const publicKey = createPublicKey(privateKey);
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return {
    available: true, privateKey, publicKey, origin, keyEnv,
    publicKeySpki: spki.toString('base64'),
    keyId: SIGNATURE_ALGORITHM + ':' + sha256Hex(spki).slice(0, 16),
  };
}

export function publicKeyFromSpki(base64) {
  const der = Buffer.from(String(base64 || ''), 'base64');
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  return { key, keyId: SIGNATURE_ALGORITHM + ':' + sha256Hex(der).slice(0, 16) };
}

export function generateAuditKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return {
    privateKey: pkcs8.toString('base64'),
    publicKey: spki.toString('base64'),
    keyId: SIGNATURE_ALGORITHM + ':' + sha256Hex(spki).slice(0, 16),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

// —— 密钥落盘：让「签名」成为默认动作 ————————————————————————
//
// 产品自己的完整性机制，不该指望操作者记得敲 dcc audit keygen。原状是默认不配密钥，
// 于是检查点全未签名（实测一次 1822 条事件的会话：3 个检查点、签名数 0）。
// 这里在首次启动时生成一把本机 Ed25519 密钥、落在工作区内，并把它的**路径**写进
// 进程环境变量（resolveAuditKey 认 env-path），下游一律照旧工作。
//
// 边界必须说清楚：这是**本机密钥**，它证明的是「这份审计流由这个工作区签出」，
// 不是某个人的身份。密钥与审计流同处一个工作区，能防第三方改内容，
// **不能**防拿到磁盘的人连密钥一起换 —— 要跨组织抵赖，请用 dcc audit pubkey
// 把公钥带外固定。但无论如何，它都比「全是未签名」强，也不会因为忘敲一条命令而失效。
export const DEFAULT_AUDIT_KEY_FILE = 'audit-key.pem';

// 本进程上一次绑定的密钥文件路径。用途单一但必须有：一个进程里可能先后装配**不同**的
// 工作区（测试就是如此），若只判断「环境变量已存在」就跳过，第二个工作区会悄悄用上
// 第一个的密钥 —— 那种串味比不签名更难查。
let boundKeyFile = null;

export async function ensureAuditKey(home, { keyEnv = DEFAULT_KEY_ENV, keyPath = null, environment = process.env } = {}) {
  const declared = environment?.[keyEnv];
  // 操作者自己设过（且不是我们上一轮绑的）→ 一律尊重：不生成、不覆盖、不报警。
  if (declared !== undefined && declared !== null && String(declared).trim() && declared !== boundKeyFile) {
    return { installed: false, source: 'operator', ...resolveAuditKey(environment, { keyEnv }) };
  }
  const file = keyPath
    ? (isAbsolute(keyPath) ? keyPath : join(home, keyPath))
    : join(home, DEFAULT_AUDIT_KEY_FILE);
  let created = false;
  if (!existsSync(file)) {
    const key = generateAuditKey();
    await mkdir(dirname(file), { recursive: true });
    try {
      // wx：绝不覆盖一把已经在用的密钥。并发时让先到的赢。
      await writeFile(file, key.privateKeyPem, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
      created = true;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
  }
  environment[keyEnv] = file;
  boundKeyFile = file;
  return { installed: true, created, path: file, ...resolveAuditKey(environment, { keyEnv }) };
}

export function signPayload(privateKey, payload) {
  return cryptoSign(null, Buffer.from(canonicalJson(payload), 'utf8'), privateKey).toString('base64');
}

export function verifyPayload(publicKey, payload, signature) {
  try { return cryptoVerify(null, Buffer.from(canonicalJson(payload), 'utf8'), publicKey, Buffer.from(String(signature), 'base64')); }
  catch { return false; }
}

// —— 检查点 ————————————————————————————————————————————————

export function checkpointPayload({ covers, at, keyId, previousCheckpoint }) {
  return { version: 1, covers, at, key_id: keyId ?? null, previous_checkpoint: previousCheckpoint ?? null };
}

export function lastCheckpointEvent(events) {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    if (events[index].type === CHECKPOINT_TYPE) return events[index];
  }
  return null;
}

export function lastCheckpointOf(events) {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    if (event.type === CHECKPOINT_TYPE && event.payload?.checkpoint?.covers?.hash) return event.payload.checkpoint;
  }
  return null;
}

// 取得可信时间戳。它是**增强**而不是单点故障：TSA 不可达时检查点照样写入，
// 但时间戳字段会带着失败原因落盘，audit verify 会把它标出来，不会假装成功。
async function obtainTimestamp(network, config, imprint, store) {
  if (!config || config.enabled === false) return null;
  const url = config.url || DEFAULT_TSA_URL;
  const base = { imprint, url, obtainedAt: new Date().toISOString() };
  if (!network) return { ...base, ok: false, error: 'TS_NETWORK_UNAVAILABLE', reason: '运行时未装配网络客户端' };
  try {
    const result = await requestTimestamp(network, imprint, {
      url,
      timeoutMs: config.timeoutMs || 15000,
      policyId: config.policyId || null,
      correlation: { sessionId: null, runId: null },
      signal: store?.auditSignal || null,
    });
    const parsed = verifyTimestampToken(result.token, {
      expectedImprint: imprint,
      pinnedFingerprint: config.certFingerprint || null,
    });
    return {
      ...base,
      token: result.token.toString('base64'),
      genTime: parsed.genTime || null,
      serial: parsed.serialNumber || null,
      policy: parsed.policy || null,
      signer: parsed.signer ? { subject: parsed.signer.subject, fingerprint256: parsed.signer.fingerprint256 } : null,
      rootFingerprint: parsed.rootFingerprint || null,
      verified: parsed.verified || {},
      ok: parsed.ok === true,
      ...(parsed.ok ? {} : { error: parsed.error || 'TS_LOCAL_VERIFY_FAILED', reason: String(parsed.message || '令牌本地校验未通过').slice(0, 300) }),
    };
  } catch (error) {
    return { ...base, ok: false, error: error.code || 'TS_FAILED', reason: String(error.message || error).slice(0, 300) };
  }
}

// 追加一个签名检查点：签署的是"当前链头 + 前一个检查点"，因此删检查点、换检查点、改链头都会暴露。
export async function appendCheckpoint(store, { reason = 'manual', keyEnv = DEFAULT_KEY_ENV, environment = process.env, network = null, timestamp = null } = {}) {
  const resolved = resolveAuditKey(environment, { keyEnv });
  let built = null;
  // 全程在事件流的写锁内完成：读事件流、算前序、签名、取时间戳、追加。
  // 之前读在锁外，N 个进程并发签出来的检查点前序会全指向同一处，
  // audit verify 报「检查点序列可能被删改」—— 并发用一次就被判成篡改。
  const event = await store.appendDerived(async ({ events }) => {
    const chained = events.filter(item => chainOf(item));
    if (!chained.length) { built = { skipped: true, reason: 'NO_CHAIN', message: '事件流尚未建立哈希链，未产生检查点' }; return null; }
    const head = chained[chained.length - 1];
    const previous = lastCheckpointOf(events);
    const covers = { seq: head.chain.seq, hash: head.chain.hash, count: head.chain.seq };
    const payload = checkpointPayload({
      covers, at: new Date().toISOString(),
      keyId: resolved.available ? resolved.keyId : null,
      previousCheckpoint: previous?.covers?.hash ?? null,
    });
    const signature = resolved.available ? signPayload(resolved.privateKey, payload) : null;
    // 时间戳锚定的是「被签名的那份载荷」：先签名，再对规范化载荷取时间戳。
    // 这样 TSA 证明的是「这个检查点在 TSA 时刻已经存在」，而不是事后补写的。
    const stamp = await obtainTimestamp(network, timestamp, sha256Hex(canonicalJson(payload)), store);
    built = { payload, signature, covers, stamp };
    return {
      type: CHECKPOINT_TYPE, source: 'audit-chain',
      meta: { noCheckpoint: true },
      payload: {
        checkpoint: payload, signature, signed: Boolean(signature),
        public_key: resolved.available ? resolved.publicKeySpki : null,
        key_env: resolved.available ? resolved.keyEnv : null,
        reason,
        unsigned_reason: resolved.available ? null : resolved.reason,
        timestamp: stamp,
      },
    };
  });
  if (!event) return built;
  return { event, signed: Boolean(built.signature), payload: built.payload, signature: built.signature,
    keyId: resolved.available ? resolved.keyId : null,
    unsignedReason: resolved.available ? null : resolved.reason, covers: built.covers, reason, timestamp: built.stamp };
}

// —— 校验 ————————————————————————————————————————————————

export function verifyChainEvents(events, { pinnedPublicKey = null, pinnedTsaCert = null } = {}) {
  const chained = events.filter(event => chainOf(event));
  const result = {
    chained: chained.length, legacy: events.length - chained.length,
    checkpoints: 0, signedCheckpoints: 0, unsignedCheckpoints: 0,
    verifiedSignatures: 0, keyIds: [], anchor: null, problems: [], ok: true,
  };
  // 导入事件带着合法的链，光验链分辨不出来。必须单独统计，否则一份伪造的 JSONL
  // 导入之后就再也认不出来了 —— 那等于把"每条链上事件都是可信事实"这个前提作废。
  const importedEvents = events.filter(event => event.meta && event.meta.imported);
  result.imported = importedEvents.length;
  result.importedSources = [...new Set(importedEvents.map(event => String((event.meta.imported && event.meta.imported.source) || 'unknown')))].slice(0, 8);
  if (importedEvents.length) {
    result.problems.push({
      severity: 'warning', code: 'AUDIT_IMPORTED_EVENTS',
      message: '事件流里有 ' + importedEvents.length + ' 条导入事件（来源：' + result.importedSources.join('、') + '）。'
        + '它们由 dcc import legacy 写入并已正常接链，链本身无法分辨真伪，引用前请人工确认来源。',
    });
  }
  if (!chained.length) {
    result.ok = true;
    result.note = '事件流尚未建立哈希链（历史数据或链被关闭）。';
    return result;
  }
  let expectedSeq = 1;
  let prev = GENESIS;
  // shared-v1 的链在 meta.chain，native-v2 在顶层；统一用 chainOf 取，不能直接读 event.chain。
  const linked = chained.map(event => ({ event, chain: chainOf(event) }));
  const bySeq = new Map();
  for (const entry of linked) bySeq.set(entry.chain.seq, entry);
  for (const entry of linked) {
    const { event, chain } = entry;
    if (chain.seq !== expectedSeq) {
      result.problems.push({ seq: chain.seq, code: 'AUDIT_CHAIN_GAP', message: '链序号不连续：期望 ' + expectedSeq + '，实际 ' + chain.seq });
      result.ok = false;
      break;
    }
    if (chain.prev !== prev) {
      result.problems.push({ seq: chain.seq, code: 'AUDIT_CHAIN_PREV_MISMATCH', message: '前序哈希不匹配：期望 ' + String(prev).slice(0, 16) + '，实际 ' + String(chain.prev).slice(0, 16) });
      result.ok = false;
      break;
    }
    const recomputed = computeEventHash(event, chain);
    if (recomputed !== chain.hash) {
      result.problems.push({ seq: chain.seq, code: 'AUDIT_CHAIN_HASH_MISMATCH', message: '事件内容哈希不匹配（第 ' + chain.seq + ' 条，type=' + event.type + '）' });
      result.ok = false;
      break;
    }
    if (chain.genesis) result.anchor = chain.genesis;
    expectedSeq += 1;
    prev = chain.hash;
  }
  let previousCheckpoint = null;
  for (const entry of linked) {
    const { event, chain } = entry;
    if (event.type !== CHECKPOINT_TYPE) continue;
    const payload = event.payload || {};
    const checkpoint = payload.checkpoint;
    if (!checkpoint || !checkpoint.covers) {
      result.problems.push({ seq: chain.seq, code: 'AUDIT_CHECKPOINT_INVALID', message: '检查点缺少 covers 结构' });
      result.ok = false;
      continue;
    }
    result.checkpoints += 1;
    if (checkpoint.previous_checkpoint !== (previousCheckpoint?.covers?.hash ?? null)) {
      result.problems.push({ seq: chain.seq, code: 'AUDIT_CHECKPOINT_CHAIN_BROKEN', message: '检查点前序引用不匹配，检查点序列可能被删改' });
      result.ok = false;
    }
    const covered = bySeq.get(checkpoint.covers.seq);
    if (!covered || covered.chain.hash !== checkpoint.covers.hash) {
      result.problems.push({ seq: chain.seq, code: 'AUDIT_CHECKPOINT_COVERAGE_MISMATCH', message: '检查点声明的覆盖链头与链上实际内容不一致' });
      result.ok = false;
    }
    if (checkpoint.key_id) result.keyIds.push(checkpoint.key_id);
    if (!payload.signed || !payload.signature) {
      result.unsignedCheckpoints += 1;
      result.problems.push({ seq: chain.seq, severity: 'warning', code: 'AUDIT_CHECKPOINT_UNSIGNED', message: '检查点未签名（' + (payload.unsigned_reason || '原因未知') + '）' });
    } else {
      result.signedCheckpoints += 1;
      let publicKey = null;
      let source = 'embedded';
      if (pinnedPublicKey) {
        if (pinnedPublicKey.keyId !== checkpoint.key_id) {
          result.problems.push({ seq: chain.seq, code: 'AUDIT_KEY_MISMATCH', message: '检查点使用了 ' + checkpoint.key_id + '，与固定公钥 ' + pinnedPublicKey.keyId + ' 不一致' });
          result.ok = false;
          previousCheckpoint = checkpoint;
          continue;
        }
        publicKey = pinnedPublicKey.key; source = 'pinned';
      } else if (payload.public_key) {
        try { publicKey = publicKeyFromSpki(payload.public_key).key; }
        catch { publicKey = null; }
      }
      if (!publicKey) {
        result.problems.push({ seq: chain.seq, code: 'AUDIT_SIGNATURE_UNVERIFIABLE', message: '无法获得公钥，签名未校验' });
        result.ok = false;
      } else if (!verifyPayload(publicKey, checkpoint, payload.signature)) {
        result.problems.push({ seq: chain.seq, code: 'AUDIT_SIGNATURE_INVALID', message: '签名校验失败' });
        result.ok = false;
      } else {
        result.verifiedSignatures += 1;
        if (source === 'embedded') result.embeddedOnly = true;
      }
    }
    // 可信时间戳：令牌存在就必须能验通；没有令牌只报警告，不把网络故障误判成篡改。
    const stamp = payload.timestamp;
    result.timestamps ||= 0;
    result.verifiedTimestamps ||= 0;
    result.unsignedTimestamps ||= 0;
    result.untimestampedCheckpoints ||= 0;
    if (stamp?.token) {
      result.timestamps += 1;
      const imprint = sha256Hex(canonicalJson(checkpoint));
      const verified = verifyTimestampToken(Buffer.from(stamp.token, 'base64'), {
        expectedImprint: imprint,
        pinnedFingerprint: pinnedTsaCert || null,
      });
      if (verified.ok) {
        result.verifiedTimestamps += 1;
        if (verified.genTime) result.latestTsaTime = verified.genTime;
      } else {
        result.problems.push({ seq: chain.seq, severity: 'error', code: 'AUDIT_TIMESTAMP_INVALID',
          message: '可信时间戳校验失败：' + (verified.error || 'TS_VERIFY_FAILED') + (verified.message ? ' —— ' + verified.message : '') });
        result.ok = false;
      }
    } else if (stamp) {
      result.timestamps += 1;
      result.unsignedTimestamps += 1;
      result.problems.push({ seq: chain.seq, severity: 'warning', code: 'AUDIT_TIMESTAMP_MISSING',
        message: '检查点未取得可信时间戳（' + (stamp.error || '未知') + '）：' + (stamp.reason || '') });
    } else {
      result.untimestampedCheckpoints += 1;
    }
    previousCheckpoint = checkpoint;
  }
  return result;
}

// 文件级校验：额外比对创世锚点，确认"建链之前的历史内容"没有被改动。
export async function verifyEventChain(path, { pinnedPublicKey = null, pinnedTsaCert = null } = {}) {
  const info = await stat(path).catch(() => null);
  if (!info) return { ok: true, events: 0, chained: 0, legacy: 0, checkpoints: 0, signedCheckpoints: 0, unsignedCheckpoints: 0, verifiedSignatures: 0, keyIds: [], problems: [], note: '事件流文件不存在。' };
  if (info.size > MAX_VERIFY_BYTES) throw chainError('AUDIT_CHAIN_TOO_LARGE', '事件流超过 ' + (MAX_VERIFY_BYTES / 1024 / 1024) + ' MiB，请分段后校验');
  const buffer = await readFile(path);
  const text = buffer.toString('utf8');
  const lines = text.split(/\r?\n/);
  const events = [];
  let broken = 0;
  for (const line of lines) {
    if (!line.trim()) continue;
    // 必须先归一化：磁盘上是 shared-v1 还是 native-v2，决定了字段叫 run_id 还是 runId。
    // 直接拿原始 JSON 算哈希，shared-v1 的事件流会整体误报为"内容被改动"。
    try { events.push(normalizeLegacyEvent(JSON.parse(line))); } catch { broken += 1; }
  }
  const result = verifyChainEvents(events, { pinnedPublicKey, pinnedTsaCert });
  result.events = events.length;
  result.broken = broken;
  result.bytes = info.size;
  if (broken) {
    result.problems.push({ code: 'AUDIT_CHAIN_BROKEN_LINE', message: '存在 ' + broken + ' 行无法解析，链完整性不可判定' });
    result.ok = false;
  }
  if (result.anchor) {
    const prefix = buffer.subarray(0, result.anchor.bytes);
    const actual = sha256Hex(prefix);
    if (actual !== result.anchor.sha256) {
      result.problems.push({ code: 'AUDIT_ANCHOR_MISMATCH', message: '创世锚点不匹配：建立链之前的历史内容已被改动' });
      result.ok = false;
    } else {
      result.anchorVerified = true;
    }
  }
  return result;
}

export function formatVerification(result) {
  const lines = [];
  if (!result.chained) {
    lines.push('哈希链：未建立（' + (result.note || '历史数据') + '）');
    lines.push('事件：' + (result.events ?? 0) + ' 条' + (result.broken ? '，坏行 ' + result.broken : ''));
    return lines.join('\n');
  }
  lines.push('哈希链：' + result.chained + ' 条链式事件' + (result.legacy ? '（另有 ' + result.legacy + ' 条建链前的历史事件）' : ''));
  if (result.anchor) lines.push('创世锚点：' + result.anchor.events + ' 条历史事件 / ' + result.anchor.bytes + ' 字节，sha256 ' + String(result.anchor.sha256).slice(0, 16)
    + (result.anchorVerified ? ' — 未被改动' : result.anchorVerified === false ? ' — 已改动' : ''));
  lines.push('签名检查点：' + result.checkpoints + ' 个（已签名 ' + result.signedCheckpoints + '，未签名 ' + result.unsignedCheckpoints + '，签名校验通过 ' + result.verifiedSignatures + '）');
  if (result.keyIds?.length) lines.push('签名密钥：' + [...new Set(result.keyIds)].join('、'));
  if (result.embeddedOnly) lines.push('提示：使用事件流内嵌公钥校验。要达到「连密钥一起重写也能发现」，请用 --pubkey 固定外部公钥。');
  if (result.checkpoints) {
    lines.push('可信时间戳：' + (result.timestamps || 0) + ' 个（校验通过 ' + (result.verifiedTimestamps || 0) + '，未取得 ' + (result.unsignedTimestamps || 0)
      + '，无时间戳检查点 ' + (result.untimestampedCheckpoints || 0) + '）' + (result.latestTsaTime ? '，最近 TSA 时间 ' + result.latestTsaTime : ''));
  }
  if (result.imported) {
    lines.push('导入事件：' + result.imported + ' 条 —— 不是本机产生的（来源 ' + (result.importedSources || []).join('、')
      + '），引用时请与原生事件分开处理');
  }
  const errors = result.problems.filter(problem => problem.severity !== 'warning');
  const warnings = result.problems.filter(problem => problem.severity === 'warning');
  lines.push('结论：' + (result.ok
    ? '链完整' + (result.verifiedSignatures ? '，签名有效' : '') + (result.verifiedTimestamps ? '，可信时间戳有效' : '')
    : '存在 ' + errors.length + ' 个完整性问题'));
  for (const problem of errors.slice(0, 10)) lines.push('  ✖ [' + problem.code + '] ' + problem.message);
  for (const problem of warnings.slice(0, 10)) lines.push('  ⚠ [' + problem.code + '] ' + problem.message);
  return lines.join('\n');
}
