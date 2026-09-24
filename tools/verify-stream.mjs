#!/usr/bin/env node

// 校验一条**裸事件流**（没有信任包时用这个）。
//
// 与 verify.mjs 的分工：
//   verify.mjs        校验「信任包」——包内校验和、清单指纹、清单签名、检查点签名与时间戳、以及事件流链，
//                     对应的是「有人把一整套证明材料交给了你」。
//   verify-stream.mjs 只校验事件流本身的哈希链，不需要信任包，适合「我手上就有一份 events.jsonl」。
//
// 用法: node tools/verify-stream.mjs <事件流路径> [--pubkey <ed25519:…>] [--json]
// 退出码: 0 = 链完整；2 = 存在问题；1 = 读不到或用法错误。

import { resolve } from 'node:path';
import { verifyEventChain, formatVerification } from '../src/audit-chain.mjs';

function parseArgs(argv) {
  const options = { json: false, file: null, pubkey: null };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--json') { options.json = true; continue; }
    if (token === '--pubkey') { options.pubkey = argv[index + 1] || null; index += 1; continue; }
    if (token.startsWith('--')) throw new Error('未知选项 ' + token);
    if (!options.file) options.file = token;
  }
  return options;
}

let options;
try { options = parseArgs(process.argv.slice(2)); }
catch (error) { console.error(error.message); process.exit(1); }
if (!options.file) {
  console.error('用法: node tools/verify-stream.mjs <事件流路径> [--pubkey <ed25519:…>] [--json]');
  process.exit(1);
}
try {
  const result = await verifyEventChain(resolve(options.file), { pinnedPublicKey: options.pubkey });
  console.log(options.json ? JSON.stringify(result, null, 2) : formatVerification(result));
  if (!result.ok) process.exitCode = 2;
} catch (error) {
  console.error('校验无法完成：' + error.message);
  process.exitCode = 1;
}
