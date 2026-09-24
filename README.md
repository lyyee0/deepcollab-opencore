本项目旨在提供非破坏性AI安全合规审计，坚决反对任何未授权的真实攻击。

# DeepCollab OpenCore

DeepCollab OpenCore 是一份面向 Agent 工程师的**举证与验证参考实现**。它关心的不是“怎样攻击目标”，而是 Agent 调用工具之后，怎样留下可独立复核、可定位篡改、不会顺手复制敏感正文的证据。

运行要求：Node.js 20 或更高版本。运行时代码只使用 Node.js 内置模块，不需要安装第三方依赖。

## 它解决什么问题

Agent 会把模型输出转换成真实动作。仅保存一段对话或最终报告，无法回答这些关键问题：

- 动作是谁、在哪个会话中提出的？
- 请求是否经过注册表、角色、参数形状和预算检查？
- 被拒绝的动作是否也留下记录？
- 事件流交付之后有没有被删改或重排？
- 检查点签名是否有效，验证者有没有固定外部公钥？
- 记录是否在落盘前完成了凭据脱敏？

本仓库用五个可以单独复用的部件回答这些问题：

1. 追加式 JSONL 事件流；
2. 基于稳定序列化的 SHA-256 前向哈希链；
3. Ed25519 签名检查点与可选的 RFC 3161 时间戳验证；
4. 写盘前、交给模型前都执行的结构化脱敏；
5. “先审计、后执行”的 Tool Gateway 策略骨架。

## 它明确不做什么

这不是 DeepCollab 完整产品，也不是扫描器、漏洞利用框架或攻击编排器。

- 不包含端口扫描、口令尝试、漏洞利用、持久化或横向移动能力；
- 不包含真实目标适配器，示例适配器只读写 Demo 自己的本地目录；
- 不发起攻击，不为任何未经授权的行为提供入口；
- `src/` 与 `tools/` 在代码层面不导入 `node:http`、`node:https`、`node:net`、`node:tls`、`node:dgram`、`node:http2` 或 `node:child_process`，因此仓库自身既不能建立网络连接，也不能启动子进程；
- `src/timestamp.mjs` 只负责构造和校验 RFC 3161 数据。若集成方需要取得时间戳，必须显式注入自己的受控网络客户端；
- 哈希链能发现局部删改，但不能证明记录内容为真、行为合法或签名者的自然人身份；
- 若验证者没有从带外渠道固定公钥，事件流内嵌公钥只能证明“内部自洽”，不能抵抗连密钥一起重建。

## 三个可运行入口

先克隆仓库并确认 Node.js 版本：

```bash
git clone https://github.com/lyyee0/deepcollab-opencore.git
cd deepcollab-opencore
node --version
```

### 1. 跑完整离线 Demo

```bash
npm run demo
```

Demo 不联网，在临时目录中依次完成六步：写入事件、通过 Tool Gateway 尝试四个动作、生成本机签名密钥、签检查点、离线校验、改动一个字节后再次校验。最后一步应明确报告第 6 条事件被改动。

如需保留本次 Demo 的工作区，可显式指定一个被 `.gitignore` 排除的目录：

```bash
node examples/run-demo.mjs ./demo-workspace
```

### 2. 校验一份裸事件流

```bash
node tools/verify-stream.mjs examples/demo-event-stream.jsonl
```

也可以运行等价的 npm 脚本：

```bash
npm run verify:stream
```

校验器会检查事件序号、前向哈希、事件内容哈希、检查点链和 Ed25519 签名。样例使用合成数据，预期结论为“链完整，签名有效”。

### 3. 校验一个信任包

```bash
node tools/verify.mjs --dir <信任包目录>
```

信任包是集成方导出的外部输入，应至少包含 `trust-bundle.json` 与 `SHA256SUMS.txt`。它可以选择携带事件流副本、公钥和 RFC 3161 令牌。校验器退出码约定：`0` 表示通过（可能有警告），`2` 表示存在完整性问题，`1` 表示用法或读取错误。

若通过 npm 脚本调用：

```bash
npm run verify -- --dir <信任包目录>
```

裸事件流与信任包是两个不同输入：前者使用 `verify-stream.mjs`，后者使用 `verify.mjs`。

## 事件流格式与验签原理

每行是一条 JSON 事件。以下仅展示最小结构：

```json
{
  "schemaVersion": "2.0",
  "id": "event-0001",
  "timestamp": "2026-01-01T00:00:00.000Z",
  "runId": "run-001",
  "sessionId": "session-001",
  "source": "my-agent",
  "type": "tool.action_requested",
  "payload": { "tool": "read_local_record", "risk": "local" },
  "meta": {},
  "chain": {
    "seq": 1,
    "prev": "genesis",
    "algorithm": "sha256",
    "hash": "<64 位十六进制摘要>"
  }
}
```

`src/canonical.mjs` 对参与哈希的对象执行稳定序列化；`src/audit-chain.mjs` 把上一条事件的哈希、当前序号和当前事件内容一起计算成新的链头。因此修改内容、删除中间事件或交换顺序都会破坏后续校验。

检查点对当时的链头和序号做 Ed25519 签名。验证强度分三层：

1. **哈希链：**发现事件流内部的删改与重排；
2. **签名检查点：**证明某把私钥签署过当时的链头；
3. **外部固定：**验证者通过其他可信渠道取得并固定公钥，才能抵抗事件流与内嵌密钥一起被替换。

RFC 3161 时间戳是可选增强：它能证明某个检查点载荷不晚于第三方签发时间存在，但不能证明事件实际发生时间或业务内容真实性。

完整格式见 [事件流格式标准](docs/event-log-spec.md)，验证语义见 [审计验证框架](docs/audit-verification.md)。

## 如何接进自己的项目

### 1. 建立事件存储

```js
import { EventStore } from './src/event-log.mjs';

const store = new EventStore({
  eventPath: './workspace/events.jsonl',
  projectionPath: './workspace/context.json',
});

await store.append({
  type: 'agent.action_requested',
  source: 'my-agent',
  sessionId: 'session-001',
  runId: 'run-001',
  payload: { tool: 'read_local_record', risk: 'local' },
});
```

`EventStore` 默认开启哈希链，并用本地锁保护追加写。事件的 `payload` 必须在进入这里之前去掉不该留存的原文。

### 2. 在唯一动作入口接入 Tool Gateway

```js
import { ToolGateway } from './src/gateway.mjs';
import { createRequestBudget } from './src/budget.mjs';

const budget = createRequestBudget({
  maxRequestsPerSession: 100,
  requestsPerMinute: 20,
});
const gateway = new ToolGateway({ store, budget });

gateway.register({
  name: 'read_local_record',
  roles: ['observer'],
  risk: 'local',
  effects: ['read-local'],
  requestCost: () => 0,
  validate: (args) => ({ id: String(args.id) }),
  audit: (args) => ({ id: args.id }),
  execute: async (args) => ({ id: args.id, found: false }),
});
```

生产适配器必须由集成方自己实现，并负责参数复验、最小权限和输出裁剪。不要让模型直接提供命令、参数数组、环境变量或任意 URL。

### 3. 签名并验证

```js
import {
  appendCheckpoint,
  ensureAuditKey,
  verifyEventChain,
} from './src/audit-chain.mjs';

await ensureAuditKey('./workspace');
await appendCheckpoint(store, { reason: 'manual' });

const result = await verifyEventChain('./workspace/events.jsonl');
if (!result.ok) throw new Error('事件流完整性校验失败');
```

Demo 为方便演示把私钥放在工作区内。真实集成应把私钥放到受控位置，并通过 `DEEPCOLLAB_AUDIT_KEY` 或自己的密钥管理层注入；向第三方交付时只交公钥，不交私钥。

更完整的接入步骤、信任包参数和故障排查见 [部署与演示](docs/deploy-and-demo.md)。架构边界见 [核心架构](docs/architecture.md)。

## 目录导览

```text
.
├── src/
│   ├── canonical.mjs       稳定序列化
│   ├── event-codec.mjs     事件磁盘编码与兼容读取
│   ├── event-log.mjs       追加写、文件锁与链式事件存储
│   ├── audit-chain.mjs     哈希链、Ed25519 检查点与验证
│   ├── timestamp.mjs       RFC 3161 编解码与校验
│   ├── redact.mjs          文本、结构化字段与流式脱敏
│   ├── gateway.mjs         Tool Gateway 参考实现
│   ├── budget.mjs          RoE 请求预算
│   └── local-paths.mjs     本地路径约束
├── tools/
│   ├── verify-stream.mjs   裸事件流校验器
│   └── verify.mjs          信任包校验器
├── examples/
│   ├── run-demo.mjs
│   ├── demo-event-stream.jsonl
│   └── demo-config.example.json
├── docs/
│   ├── architecture.md
│   ├── audit-verification.md
│   ├── deploy-and-demo.md
│   └── event-log-spec.md
├── SECURITY.md
├── NOTICE
├── LICENSE
└── package.json
```

## 许可证

Apache-2.0。详见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。
