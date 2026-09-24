#!/usr/bin/env node

// 端到端 Demo —— 完全离线，用本仓库的代码当场造一条证据流，然后：
//   1) 让「模型」通过 Tool Gateway 试几个动作（有的成功，有的被拦下）；
//   2) 签一个检查点；
//   3) 验一遍：哈希链是否完整、检查点签名是否有效；
//   4) 改动一个字节，再验一遍：**必须**报出断在哪里。
//
// 第 4 步才是这个项目存在的理由。一次测试「跑完了」和「跑得对」之间差的那份凭证，
// 就是第 3 步能给出的东西；而只要你还能在第 4 步被抓住，第 3 步的「通过」才有意义。
//
// 用法：
//   node examples/run-demo.mjs              跑在临时目录里，跑完告诉你文件在哪
//   node examples/run-demo.mjs <工作区目录>  跑在指定目录里（会往里写文件）
//
// 全程不联网。所有数据都是合成的，示例域名用 example.com。
// 注意：每次运行都会新生成一把签名密钥，所以密钥 ID 每次都不同 —— 那是正常的。

import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { EventStore } from '../src/event-log.mjs';
import { appendCheckpoint, ensureAuditKey, formatVerification, verifyEventChain } from '../src/audit-chain.mjs';
import { createDemoGateway } from '../src/gateway.mjs';
import { redactCredentialFields } from '../src/redact.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const rule = title => console.log('\n── ' + title + ' ' + '─'.repeat(Math.max(4, 58 - title.length)));

// 配置是可选的：没有就按默认值跑。examples/demo-config.example.json 是它的样子。
const configPath = join(HERE, 'demo-config.example.json');
let config = { roe: {}, demoRoot: 'demo-root' };
if (existsSync(configPath)) {
  try { config = { ...config, ...JSON.parse(readFileSync(configPath, 'utf8')) }; }
  catch (error) { console.log('配置读不了，按默认值跑：' + error.message); }
}

const workspace = process.argv[2] ? resolve(process.argv[2]) : mkdtempSync(join(tmpdir(), 'deepcollab-demo-'));
const eventPath = join(workspace, 'events.jsonl');
const projectionPath = join(workspace, 'context.json');
const demoRoot = join(workspace, config.demoRoot || 'demo-root');

console.log('工作区: ' + workspace);

const store = new EventStore({ eventPath, projectionPath });
const sessionId = 'demo-session';
const runId = 'demo-run';

// ── 1. 会话开始 ─────────────────────────────────────────────────────────────
rule('1. 写入事件流');

// 一条「服务器把你刚提交的请求体原样回显」的响应。这类响应会经过好几条通道，
// 所以脱敏必须在**写盘之前**就做掉 —— 下面这一行的输出就是脱敏的结果。
const echoed = redactCredentialFields(JSON.stringify({
  detail: [{ loc: ['body', 'password'], msg: 'Field required', input: { username: 'alice', password: 'hunter2' } }],
}));

for (const [type, payload] of [
  ['session.started', { objective: '演示：一次受控的自查（合成数据）' }],
  ['target.authorized', { origin: 'https://example.com', basis: '书面授权' }],
  ['auth.login_failed', { response: echoed }],
]) {
  const event = await store.append({ type, source: 'demo', sessionId, runId, payload });
  console.log('  第 ' + event.chain.seq + ' 条  ' + type);
}

console.log('');
console.log('  回显脱敏后的样子:');
console.log('    ' + echoed);

// ── 2. 让「模型」通过 Tool Gateway 试几个动作 ───────────────────────────────
rule('2. 通过 Tool Gateway 试四个动作');

mkdirSync(demoRoot, { recursive: true });
writeFileSync(join(demoRoot, 'readme.txt'), '这是一个示例文件，内容无关紧要。' + String.fromCharCode(10), 'utf8');

const gateway = createDemoGateway({ store, demoRoot, roe: config.roe });
const observer = { sessionId, runId, roleId: 'observer' };
const pioneer = { sessionId, runId, roleId: 'pioneer' };

const allowed = await gateway.execute(
  { tool: 'demo_read_file', arguments: { path: 'readme.txt' }, modelToolCallId: 'call_demo_1' }, observer);
console.log('  ✓ demo_read_file 执行成功：读到 ' + allowed.result.bytes + ' 字节');
console.log('     正文**没有**进事件流，落盘的是字节数与 SHA-256 —— 证据要能证明发生过什么，');
console.log('     但不该顺手把读到的内容复制成一份新的副本。');

for (const [label, request, context] of [
  ['角色闸', { tool: 'demo_write_note', arguments: { name: 'note', text: 'hi' }, modelToolCallId: 'call_demo_2' }, observer],
  ['形状闸', { tool: 'demo_read_file', arguments: { path: 'readme.txt' }, command: 'anything' }, observer],
  ['预算闸', { tool: 'demo_batch', arguments: { count: 900 }, modelToolCallId: 'call_demo_4' }, pioneer],
]) {
  try {
    await gateway.execute(request, context);
    console.log('  ✗ ' + label + ' 本该拦下这个动作，却放行了 —— 这是缺陷');
  } catch (error) {
    console.log('  ✗ ' + label + ' 拦下：' + error.code);
  }
}
console.log('');
console.log('  三次被拒同样写进了事件流（tool.action_blocked）——');
console.log('  一份只记录「成功」的日志，无法回答「它到底试过什么」。');

// ── 3. 签名密钥 ─────────────────────────────────────────────────────────────
rule('3. 生成本机签名密钥');

mkdirSync(workspace, { recursive: true });
const key = await ensureAuditKey(workspace);
console.log('  密钥文件: ' + key.path);
console.log('  密钥 ID:  ' + key.keyId + '（每次运行都不同，那是正常的）');
console.log('  本次新建: ' + (key.created ? '是' : '否（已存在，直接沿用）'));
console.log('');
console.log('  边界必须说清楚：这是**本机密钥**，它证明的是「这条流由这个工作区签出」，');
console.log('  不是某个人的身份。密钥与事件流同处一个工作区，能防第三方改内容，');
console.log('  不能防拿到磁盘的人把两样一起换掉 —— 要跨组织抵赖，必须把公钥带外固定。');

// ── 4. 签一个检查点 ─────────────────────────────────────────────────────────
rule('4. 签一个检查点');

const checkpoint = await appendCheckpoint(store, { reason: 'demo' });
console.log('  已签名: ' + checkpoint.signed);
console.log('  覆盖到: 第 ' + checkpoint.covers.seq + ' 条');
console.log('  链头:   ' + String(checkpoint.covers.hash).slice(0, 32) + '…');
console.log('  密钥 ID: ' + (checkpoint.keyId || '（未签名）'));
console.log('  可信时间戳: ' + (checkpoint.timestamp
  ? '已获取（' + (checkpoint.timestamp.genTime || '') + '）'
  : '未获取 —— 本 Demo 不联网。生产环境里它由外部时间源出证，'));
console.log('              证明「这些记录在某个第三方时刻已经存在」，本机时钟改不掉它。');

// ── 5. 离线校验 ─────────────────────────────────────────────────────────────
rule('5. 离线校验（不联网、不需要本产品）');

const first = await verifyEventChain(eventPath);
console.log(formatVerification(first));

// ── 6. 改动一个字节，再验一次 ───────────────────────────────────────────────
rule('6. 改动一个字节，再验一次');

const original = readFileSync(eventPath, 'utf8');
const needle = '"bytes":' + allowed.result.bytes;
if (!original.includes(needle)) throw new Error('演示前提不成立：事件流里找不到 ' + needle);
writeFileSync(eventPath, original.replace(needle, '"bytes":999'), 'utf8');
console.log('  把读文件那条结果里的 ' + needle + ' 改成 "bytes":999（其它一字未动）');

const second = await verifyEventChain(eventPath);
console.log(formatVerification(second));

writeFileSync(eventPath, original, 'utf8');

// ── 结论 ────────────────────────────────────────────────────────────────────
rule('结论');
console.log('  第一次: ' + (first.ok ? '链完整、签名有效' : '未通过'));
console.log('  第二次: ' + (second.ok ? '仍然通过 —— 那说明这条流根本挡不住改动，别信它' : '已报出问题'));
console.log('');
console.log('  事件流: ' + eventPath);
console.log('  密钥:   ' + key.path + '（**不要**把工作区里的私钥一起交出去）');
