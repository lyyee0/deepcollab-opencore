#!/usr/bin/env node

import { readFile } from 'node:fs/promises';

import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '../src/canonical.mjs';
import { publicKeyFromSpki, sha256Hex, verifyEventChain, verifyPayload } from '../src/audit-chain.mjs';
import { verifyTimestampToken } from '../src/timestamp.mjs';

// 独立校验脚本：验证一个信任包，不需要安装 DeepCollab，也不需要联网。
// 只用 Node 内置模块；依赖模块随包交付在 lib/ 下。
//
// 用法：
//   node verify.mjs [--dir <包目录>] [--evidence <事件流路径>]
//                   [--expect-bundle-digest <64位十六进制>]
//                   [--expect-signing-key <ed25519:...>]
//                   [--expect-tsa <证书指纹>] [--json]
//
// 退出码：0 = 全部通过（可能有警告），2 = 存在完整性问题，1 = 用法或读取错误。

export async function verifyTrustPackage(packageDir, options = {}) {
  const dir = resolve(packageDir);
  const checks = [];
  const record = (status, code, message, detail = null) => checks.push({ status, code, message, detail });
  const pass = (code, message, detail) => record('pass', code, message, detail);
  const warn = (code, message, detail) => record('warn', code, message, detail);
  const fail = (code, message, detail) => record('fail', code, message, detail);

  const readIfPresent = async path => { try { return await readFile(path); } catch { return null; } };

  // 1) 包内校验和：先确认包本身没被动过，后面的校验才有意义。
  const sumsText = await readIfPresent(join(dir, 'SHA256SUMS.txt'));
  if (sumsText === null) fail('PACKAGE_SUMS_MISSING', '缺少 SHA256SUMS.txt，无法确认包内文件未被改动');
  else {
    const rows = sumsText.toString('utf8').split(/\r?\n/).filter(Boolean)
      .map(line => { const match = line.match(/^([0-9a-fA-F]{64})\s+(.+)$/); return match ? { hash: match[1].toLowerCase(), file: match[2].trim() } : null; })
      .filter(Boolean);
    const mismatched = [];
    const missing = [];
    let checked = 0;
    for (const row of rows) {
      const bytes = await readIfPresent(join(dir, row.file));
      if (bytes === null) { missing.push(row.file); continue; }
      checked += 1;
      if (sha256Hex(bytes) !== row.hash) mismatched.push(row.file);
    }
    if (mismatched.length) fail('PACKAGE_SUMS_MISMATCH', '包内有 ' + mismatched.length + ' 个文件的哈希与 SHA256SUMS.txt 不一致', mismatched.slice(0, 8));
    else if (missing.length) fail('PACKAGE_SUMS_MISSING_FILE', 'SHA256SUMS.txt 列出的 ' + missing.length + ' 个文件不存在', missing.slice(0, 8));
    else pass('PACKAGE_SUMS', '包内 ' + checked + ' 个文件与 SHA256SUMS.txt 一致');
  }

  // 2) 清单与它的指纹
  const bundleText = await readIfPresent(join(dir, 'trust-bundle.json'));
  if (bundleText === null) {
    fail('BUNDLE_MISSING', '缺少 trust-bundle.json');
    return summarize(dir, checks);
  }
  let bundle;
  try { bundle = JSON.parse(bundleText.toString('utf8')); }
  catch (error) { fail('BUNDLE_INVALID', 'trust-bundle.json 不是合法 JSON：' + error.message); return summarize(dir, checks); }

  const signature = bundle.signature || null;
  const core = { ...bundle };
  delete core.signature;
  const bundleDigest = sha256Hex(canonicalJson(core));

  if (options.expectBundleDigest) {
    const expected = String(options.expectBundleDigest).replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    if (expected === bundleDigest) pass('BUNDLE_DIGEST', '清单指纹与外部提供的值一致', bundleDigest);
    else fail('BUNDLE_DIGEST_MISMATCH', '清单指纹与外部提供的值不一致——这份包或它的清单已经被改动', { expected, actual: bundleDigest });
  } else {
    warn('BUNDLE_DIGEST_UNPINNED', '未提供 --expect-bundle-digest；包可以自证一致，但无法证明它就是你收到的那一份', bundleDigest);
  }

  // 3) 清单签名（可离线完成，不需要事件流）
  const keysById = new Map((core.signingKeys || []).map(item => [item.keyId, item]));
  let pinnedKey = null;
  if (options.expectSigningKey) {
    const wanted = String(options.expectSigningKey).trim();
    if (keysById.has(wanted)) { pinnedKey = keysById.get(wanted); pass('SIGNING_KEY_PINNED', '清单使用了外部固定的签名密钥 ' + wanted); }
    else fail('SIGNING_KEY_MISMATCH', '包内没有外部固定的签名密钥 ' + wanted, [...keysById.keys()]);
  }
  if (signature) {
    const holder = pinnedKey || keysById.get(signature.keyId);
    if (!holder) fail('SIGNING_KEY_UNKNOWN', '清单签名引用了包内不存在的密钥 ' + signature.keyId);
    else {
      const publicKey = publicKeyFromSpki(holder.publicKeySpki).key;
      if (verifyPayload(publicKey, core, signature.value)) pass('BUNDLE_SIGNATURE', '清单签名有效（' + signature.keyId + '）');
      else fail('BUNDLE_SIGNATURE_INVALID', '清单签名校验失败：清单内容与签名不匹配');
    }
  } else if (pinnedKey) {
    fail('BUNDLE_UNSIGNED', '要求固定签名密钥，但这份清单没有签名');
  } else {
    warn('BUNDLE_UNSIGNED', '清单未签名；完整性只能依赖外部提供的清单指纹');
  }

  // 4) 逐个检查点：签名与可信时间戳都可以只靠清单 + 令牌原文离线复核。
  let signedOk = 0;
  let timestampOk = 0;
  const checkpointProblems = [];
  for (const row of core.checkpoints || []) {
    const payload = {
      version: 1,
      covers: { seq: row.coversSeq, hash: row.coversHash, count: row.coversCount === undefined ? row.coversSeq : row.coversCount },
      at: row.at,
      key_id: row.keyId === undefined ? null : row.keyId,
      previous_checkpoint: row.previousCheckpoint === undefined ? null : row.previousCheckpoint,
    };
    if (row.signed && row.signature) {
      const holder = keysById.get(row.keyId);
      if (!holder) checkpointProblems.push('检查点 #' + row.coversSeq + '：包内缺少密钥 ' + row.keyId);
      else if (verifyPayload(publicKeyFromSpki(holder.publicKeySpki).key, payload, row.signature)) signedOk += 1;
      else checkpointProblems.push('检查点 #' + row.coversSeq + '：签名校验失败');
    }
    const stamp = row.timestamp;
    if (stamp && stamp.tokenFile) {
      const token = await readIfPresent(join(dir, stamp.tokenFile));
      if (!token) checkpointProblems.push('检查点 #' + row.coversSeq + '：缺少令牌文件 ' + stamp.tokenFile);
      else {
        const parsed = verifyTimestampToken(token, {
          expectedImprint: stamp.imprint || null,
          pinnedFingerprint: options.expectTsa || null,
        });
        if (parsed.ok) timestampOk += 1;
        else checkpointProblems.push('检查点 #' + row.coversSeq + '：可信时间戳校验失败（' + (parsed.error || '') + (parsed.message ? ' ' + parsed.message : '') + '）');
      }
    }
  }
  const signedRows = (core.checkpoints || []).filter(row => row.signed).length;
  if (checkpointProblems.length) fail('CHECKPOINT_FAILED', '有 ' + checkpointProblems.length + ' 个检查点未通过校验', checkpointProblems.slice(0, 8));
  else if (signedRows) pass('CHECKPOINT_SIGNATURES', signedRows + ' 个已签名检查点全部验通（离线，不依赖事件流）');
  else warn('CHECKPOINT_UNSIGNED', '清单中的检查点都没有签名；完整性只依赖哈希链');

  const stampRows = (core.checkpoints || []).filter(row => row.timestamp && row.timestamp.tokenFile).length;
  if (stampRows && timestampOk === stampRows) {
    pass('TRUSTED_TIMESTAMPS', stampRows + ' 个可信时间戳令牌全部验通，最早签发时间 ' + earliestTimestamp(core));
  } else if (stampRows) {
    fail('TRUSTED_TIMESTAMPS_INCOMPLETE', '可信时间戳 ' + timestampOk + '/' + stampRows + ' 通过');
  } else {
    warn('TRUSTED_TIMESTAMPS_NONE', '清单中没有可信时间戳令牌');
  }

  // 5) 事件流与哈希链（需要证据副本；没有就只能验到上一步）
  const evidencePath = options.evidence
    ? resolve(options.evidence)
    : (core.scope && core.scope.evidence && core.scope.evidence.included ? join(dir, core.scope.evidence.path) : null);
  if (!evidencePath) {
    warn('EVIDENCE_ABSENT', '本包未包含事件流副本，且未提供 --evidence；哈希链本身未能校验');
  } else {
    const bytes = await readIfPresent(evidencePath);
    if (!bytes) fail('EVIDENCE_MISSING', '找不到事件流：' + evidencePath);
    else {
      // 哈希不一致时仍然继续跑链校验：接收方需要同时知道"这不是清单里那份"和"它具体哪里断了"。
      if (core.scope.evidence.included && sha256Hex(bytes) !== core.scope.evidence.sha256) {
        fail('EVIDENCE_HASH_MISMATCH', '事件流的 SHA-256 与清单记录不一致');
      } else if (core.scope.evidence.included) {
        pass('EVIDENCE_HASH', '事件流 SHA-256 与清单一致');
      }
      const chain = await verifyEventChain(evidencePath, {
        pinnedTsaCert: options.expectTsa || null,
      });
      if (chain.ok) pass('EVENT_CHAIN', '事件流哈希链完整：' + chain.chained + ' 条链式事件' + (chain.legacy ? '，创世锚点覆盖 ' + chain.legacy + ' 条历史事件' : ''));
      else fail('EVENT_CHAIN_BROKEN', '事件流哈希链存在问题', chain.problems.slice(0, 8));
      if (chain.anchor && !chain.anchorVerified) fail('ANCHOR_MISMATCH', '创世锚点不匹配：建链前的历史内容已被改动');
      if (core.scope.headSeq === chain.chained && core.scope.headHash
        && (chain.problems.length === 0 || chain.problems.every(problem => problem.severity === 'warning'))) {
        pass('HEAD_MATCH', '清单记录的链头与事件流一致（第 ' + core.scope.headSeq + ' 条）');
      } else if (chain.chained !== core.scope.headSeq) {
        fail('HEAD_MISMATCH', '清单声明的链式事件数 ' + core.scope.headSeq + ' 与实际 ' + chain.chained + ' 不一致');
      }
      const anchor = core.scope.genesisAnchor;
      if (anchor) {
        if (chain.anchor && chain.anchor.sha256 === anchor.sha256 && chain.anchor.bytes === anchor.bytes) pass('ANCHOR_MATCH', '创世锚点与清单一致');
        else fail('ANCHOR_MISMATCH', '创世锚点与清单不一致');
      }
    }
  }

  if (options.expectTsa) {
    const wanted = String(options.expectTsa).replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
    const known = (core.pinning && core.pinning.tsaFingerprints) || [];
    if (known.some(item => String(item).toUpperCase() === wanted)) pass('TSA_PINNED', 'TSA 证书指纹与外部固定值一致');
    else fail('TSA_MISMATCH', 'TSA 证书指纹与外部固定值不一致', { expected: wanted, actual: known });
  }

  return summarize(dir, checks, { bundleDigest, scope: core.scope, limits: core.limits });
}

function earliestTimestamp(core) {
  const times = (core.checkpoints || []).map(row => row.timestamp && row.timestamp.genTime).filter(Boolean).sort();
  return times.length ? times[0] : '未知';
}

function summarize(dir, checks, extra = {}) {
  const failed = checks.filter(check => check.status === 'fail');
  const warned = checks.filter(check => check.status === 'warn');
  return { ok: failed.length === 0, dir, checks, failed: failed.length, warned: warned.length, ...extra };
}

export function formatTrustResult(result) {
  const mark = { pass: '✓', warn: '!', fail: '✗' };
  const lines = [];
  lines.push('信任包校验：' + result.dir);
  lines.push('');
  for (const check of result.checks) lines.push('  ' + mark[check.status] + ' [' + check.code + '] ' + check.message);
  lines.push('');
  lines.push(result.ok
    ? '结论：通过（' + (result.warned ? result.warned + ' 项警告需要留意' : '无警告') + '）'
    : '结论：不通过（' + result.failed + ' 项完整性问题）');
  return lines.join('\n');
}

// 校验器只认下面这些选项。**未知选项必须报错，不能静默忽略。**
// 第三方按文档传了一个不存在的选项（例如把 dcc audit verify 的 --pubkey 用在这里），
// 如果被静默忽略，他会以为公钥已经固定住——而「固定对方公钥」正是整条信任链里
// 唯一不能出错的一步。宁可报错，也不能给出「通过」这个错误的安全感。
const KNOWN_OPTIONS = ['json', 'dir', 'evidence', 'expectBundleDigest', 'expectSigningKey', 'expectTsa'];

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--json') { options.json = true; continue; }
    if (!token.startsWith('--')) { if (!options.dir) options.dir = token; continue; }
    const key = token.slice(2).replace(/-([a-z])/g, (_m, letter) => letter.toUpperCase());
    if (!KNOWN_OPTIONS.includes(key)) {
      throw Object.assign(new Error('未知选项 --' + token.slice(2)
        + '\n可用选项：--dir <目录> --evidence <事件流> --expect-bundle-digest <指纹> --expect-signing-key <公钥> --expect-tsa <证书> --json'
        + '\n注意：--pubkey 是 dcc audit verify 的选项，不是本脚本的；本脚本用 --expect-signing-key 固定公钥。'), { code: 'UNKNOWN_OPTION' });
    }
    const next = argv[index + 1];
    if (next !== undefined && !next.startsWith('--')) { options[key] = next; index += 1; }
    else options[key] = true;
  }
  return options;
}

const isEntry = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isEntry) {
  let options;
  try { options = parseArgs(process.argv.slice(2)); }
  catch (error) { console.error(error.message); process.exit(2); }
  const dir = options.dir && options.dir !== true ? options.dir : dirname(fileURLToPath(import.meta.url));
  try {
    const result = await verifyTrustPackage(dir, {
      evidence: options.evidence, expectBundleDigest: options.expectBundleDigest,
      expectSigningKey: options.expectSigningKey, expectTsa: options.expectTsa,
    });
    console.log(options.json ? JSON.stringify(result, null, 2) : formatTrustResult(result));
    if (!result.ok) process.exitCode = 2;
  } catch (error) {
    console.error('校验无法完成：' + error.message);
    process.exitCode = 1;
  }
}
