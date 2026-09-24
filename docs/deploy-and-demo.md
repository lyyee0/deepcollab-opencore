# 部署与 Demo

本文回答四件事：**需要什么环境**、**怎么把它跑起来**、**怎么用样例做一次完整的离线验证**、**怎么把符合格式的事件写进你自己的系统**。最后一节是常见报错与排查。

本文所有命令都在干净的临时目录里实测过；所有示例一律使用合成数据（`example.com`、`192.0.2.x`、某员工）。

---

## 1. 环境要求

| 项 | 要求 | 说明 |
| --- | --- | --- |
| Node.js | **>= 20** | 见 `package.json` 的 `engines`。用 `node --version` 确认 |
| 依赖 | **无** | 本仓库只有 `devDependencies` 之外的空依赖表 —— 运行期不装任何包。校验器与示例只用 Node 内置模块 |
| 网络 | **不需要** | 除「取可信时间戳」一步外，全部离线。Demo 全程不联网 |
| 平台 | Windows / macOS / Linux 均可 | 没有平台特定的依赖 |
| 权限 | 普通用户即可 | 不需要管理员权限，不需要写系统目录 |

```bash
node --version      # 期望 v20.x 或更高
```

**为什么强调零依赖：** 这套代码的用途是「让不信任你的人也能自己验一遍」。如果校验器本身要装一堆包，那验证的第一步就变成了「你得先相信我的依赖树」。同理，它不支持也不需要任何外部服务。

---

## 2. 获取代码

```bash
git clone https://github.com/lyyee0/deepcollab-opencore.git
cd deepcollab-opencore
```

目录结构：

```text
src/       可读的实现（稳定序列化、事件编码、事件流、审计链、时间戳、脱敏、网关骨架）
tools/     两个命令行校验器
examples/  可运行示例与脱敏样例数据
docs/      架构、格式标准、验证框架、本文
```

不需要 `npm install`。要跑测试或 Demo，直接 `node` 即可。

---

## 3. 第一步：跑一遍完整往返（Demo）

```bash
npm run demo
# 等价于：node examples/run-demo.mjs
# 也可以指定工作目录：node examples/run-demo.mjs ./demo-workspace
```

它跑在临时目录里、不联网、退出码 0，分六步走。实际输出如下（密钥 ID 与临时目录路径每次运行都不同，Demo 自己会标注这一点）：

```text
工作区: <临时工作区>

── 1. 写入事件流 ──
  第 1 条  session.started
  第 2 条  target.authorized
  第 3 条  auth.login_failed

  回显脱敏后的样子:
    {"detail":[{"loc":["body","password"],"msg":"Field required","input":{"username":"alice","password":"[已隐去]"}}]}

── 2. 通过 Tool Gateway 试四个动作 ──
  ✓ demo_read_file 执行成功：读到 49 字节
     正文**没有**进事件流，落盘的是字节数与 SHA-256 —— 证据要能证明发生过什么，
     但不该顺手把读到的内容复制成一份新的副本。
  ✗ 角色闸 拦下：TOOL_DENIED
  ✗ 形状闸 拦下：GATEWAY_FIELD_DENIED
  ✗ 预算闸 拦下：TOOL_BUDGET_EXCEEDED

  三次被拒同样写进了事件流（tool.action_blocked）——
  一份只记录「成功」的日志，无法回答「它到底试过什么」。

── 3. 生成本机签名密钥 ──
  密钥文件: <临时工作区>/audit-key.pem
  密钥 ID:  ed25519:72ba3fef44af83ec（每次运行都不同，那是正常的）
  本次新建: 是

  边界必须说清楚：这是**本机密钥**，它证明的是「这条流由这个工作区签出」，
  不是某个人的身份。密钥与事件流同处一个工作区，能防第三方改内容，
  不能防拿到磁盘的人把两样一起换掉 —— 要跨组织抵赖，必须把公钥带外固定。

── 4. 签一个检查点 ──
  已签名: true
  覆盖到: 第 9 条
  链头:   4199c61f6922db00c83102aa114a16a7…
  密钥 ID: ed25519:72ba3fef44af83ec
  可信时间戳: 未获取 —— 本 Demo 不联网。生产环境里它由外部时间源出证，
              证明「这些记录在某个第三方时刻已经存在」，本机时钟改不掉它。

── 5. 离线校验（不联网、不需要本产品） ──
哈希链：10 条链式事件
签名检查点：1 个（已签名 1，未签名 0，签名校验通过 1）
签名密钥：ed25519:72ba3fef44af83ec
提示：使用事件流内嵌公钥校验。要达到「连密钥一起重写也能发现」，请用 --pubkey 固定外部公钥。
可信时间戳：0 个（校验通过 0，未取得 0，无时间戳检查点 1）
结论：链完整，签名有效

── 6. 改动一个字节，再验一次 ──
  把读文件那条结果里的 "bytes":49 改成 "bytes":999（其它一字未动）
哈希链：10 条链式事件
签名检查点：1 个（已签名 1，未签名 0，签名校验通过 1）
签名密钥：ed25519:72ba3fef44af83ec
提示：使用事件流内嵌公钥校验。要达到「连密钥一起重写也能发现」，请用 --pubkey 固定外部公钥。
可信时间戳：0 个（校验通过 0，未取得 0，无时间戳检查点 1）
结论：存在 1 个完整性问题
  ✖ [AUDIT_CHAIN_HASH_MISMATCH] 事件内容哈希不匹配（第 6 条，type=tool.action_completed）

── 结论 ──
  第一次: 链完整、签名有效
  第二次: 已报出问题

  事件流: <临时工作区>/events.jsonl
  密钥:   <临时工作区>/audit-key.pem（**不要**把工作区里的私钥一起交出去）
```
### 每一步在证明什么

**第 1 步 · 写入事件流。** 每写一条，就在写锁内立刻接上哈希链（`chain.seq` / `chain.prev` / `chain.hash`）。那行**回显脱敏后的样子**演示的是最容易被忽视的一类泄露：服务器把你刚提交的请求体原样回显（这里用的就是这种 422 响应形态），`password` 的值已被替换为 `[已隐去]`；而**兄弟字段 `loc` 里出现的凭据字段名**也会触发同样的处理。这条规则必须由所有通道共用，否则每加一条通道就多一个漏点。

**第 2 步 · 四个动作走同一个执行入口。** 这是把「策略」与「执行」分开的现场演示：1 个动作真的执行了，另外 3 个分别在三道不同的闸上被拦下 ——

| 动作 | 结果 | 拦它的是哪一道 |
| --- | --- | --- |
| `demo_read_file` | ✓ 执行成功，读到 49 字节 | —— |
| 未注册/角色不允许的工具 | ✗ `TOOL_DENIED` | **角色闸**：这个角色不持有该工具 |
| 参数里多带了一个未许可字段 | ✗ `GATEWAY_FIELD_DENIED` | **形状闸**：请求只允许 `tool` / `arguments` / `modelToolCallId` 三个字段 |
| `demo_batch` 要 900 次请求 | ✗ `TOOL_BUDGET_EXCEEDED` | **预算闸**：`maxRequestsPerSession: 500`，在执行**之前**预扣失败 |

这一格里有两个容易被忽略、但正是设计意图的点：**读到的正文没有进事件流**（落盘的是字节数与 SHA-256 —— 证据要能证明发生过什么，但不该顺手把读到的内容复制成一份新副本）；**三次被拒同样写进了事件流**（`tool.action_blocked`）。一份只记录「成功」的日志，回答不了「它到底试过什么」。

**第 3 步 · 生成本机签名密钥。** 密钥落在工作目录里的 `audit-key.pem`，**每次运行都不同**（Demo 自己也在输出里标注了这一点，所以你看到不同的 `key_id` 不是做错了）。`key_id` 是公钥的短标识，**不是身份标识** —— 见 README 的 §5.2。

**第 4 步 · 签一个检查点。** 检查点把此刻链头（第 9 条）的序号与哈希固定下来并签名；检查点之间还通过 `previous_checkpoint` 串成一条链，所以删一个、调顺序、事后补一个都会暴露。这一步没有取可信时间戳（Demo 不联网），**这不影响其余两层** —— 时间戳是增强，不是单点故障。

**第 5 步 · 离线校验。** `10 条链式事件` = 9 条业务事件 + 1 条检查点事件。整个校验只用 Node 内置模块完成，**不需要本产品、不需要联网、不需要任何外部服务**。这是「第三方离线复核」的最小可运行形态。

**第 6 步 · 改一个字节。** 只把读文件那条结果里的 `"bytes":49` 改成 `"bytes":999`，其余一字未动，链立刻在**那一条**上断裂，并指出它的序号与事件类型。这是整个项目的价值主张：不是笼统地说「被改过」，而是**精确指到第几条、哪一类事件**。

**Demo 读的同目录配置。** `examples/demo-config.example.json` 会被 `run-demo.mjs` 读取，字段缺失时用默认值，里面只有两项：`roe`（`maxRequestsPerSession: 500`、`requestsPerMinute: 60` —— 第 2 步里 `demo_batch` 要 900 次请求，就是撞在这个上限上被拒的）与 `demoRoot`。想改预算做实验，改这个文件即可。
---

## 4. 第二步：对样例事件流做一次完整的离线验证

样例文件是 `examples/demo-event-stream.jsonl`（5883 字节 / 10 条链式事件，由 Demo 生成后复制过来的合成数据，可以安全地放进版本库与截图）。

### 方式一：用校验器（推荐）

```bash
node tools/verify-stream.mjs examples/demo-event-stream.jsonl
```

实际输出：

```text
哈希链：10 条链式事件
签名检查点：1 个（已签名 1，未签名 0，签名校验通过 1）
签名密钥：ed25519:f67e70b586036004
提示：使用事件流内嵌公钥校验。要达到「连密钥一起重写也能发现」，请用 --pubkey 固定外部公钥。
可信时间戳：0 个（校验通过 0，未取得 0，无时间戳检查点 1）
结论：链完整，签名有效
```

退出码 `0` 表示链完整。逐行读法：

| 行 | 它在证明什么 |
| --- | --- |
| `哈希链：10 条链式事件` | 7 条事件全部在链上，序号连续、`prev` 首尾相接、逐条重算的哈希与写盘时一致 |
| `签名检查点：1 个（已签名 1，未签名 0，签名校验通过 1）` | 没有「未签名」的检查点混进来；这一个的签名确实由 `签名密钥` 那行的公钥验通 |
| `签名密钥：ed25519:f67e70b586036004` | 签署者是谁 —— 但它只是公钥标识，**不是身份** |
| `提示：…请用 --pubkey 固定外部公钥` | **这一行最关键。** 它说明当前结论是「与事件流里自带的公钥匹配」。一个能改事件流的人，通常也能把公钥一起换掉 —— 所以这个结论**不能**被当作来源凭据 |
| `可信时间戳：0 个（…无时间戳检查点 1）` | 这份样例没有第三方时间证人。不是失败，是这一层在这份数据上不存在 |

### 方式二：固定外部公钥再验一次

要让签名具备「来源」含义，公钥必须来自**另一条渠道**（当面、电话、纸质件、另一个邮件系统），而不是事件流本身。拿到公钥标识之后：

```bash
node tools/verify-stream.mjs examples/demo-event-stream.jsonl --pubkey ed25519:0123456789abcdef
```

公钥不一致时不会给含糊的结论，而是直接判失败（`AUDIT_KEY_MISMATCH`，退出码 `2`）。这是刻意的：<br>「链完整」和「链完整**且**由我预期的那把钥匙签的」是两句不同的话，工具不该把它们混成一句。

### 方式三：直接用库接口验（不经过命令行）

如果你要把校验嵌进自己的流水线，直接用库：

```bash
node --input-type=module -e "
  import { verifyEventChain, formatVerification } from './src/audit-chain.mjs';
  const result = await verifyEventChain('./examples/demo-event-stream.jsonl');
  console.log(formatVerification(result));
  console.log('ok =', result.ok, ' chained =', result.chained);
"
```

`verifyEventChain` 返回的是结构化结果，可直接用于自动化判定：

```js
{
  ok: true,                    // 总判定：有没有完整性问题（警告不算失败）
  chained: 10,                 // 链上事件条数
  legacy: 0,                   // 未上链的历史事件条数
  events: 10, broken: 0,       // 总条数与损坏行数
  checkpoints: 1, signedCheckpoints: 1, unsignedCheckpoints: 0,
  verifiedSignatures: 1, keyIds: ['ed25519:...'],
  timestamps: 0, verifiedTimestamps: 0, unsignedTimestamps: 0, untimestampedCheckpoints: 1,
  anchor: null,                // 创世锚点（建链之前的历史内容）
  embeddedOnly: true,          // 仅用事件流内嵌公钥校验 —— 需要外部固定时请注意这一位
  problems: [ /* 每项含 severity / code / message */ ]
}
```

做自动化时请判 `ok`，**不要**只判「有没有 problems」—— 警告也会出现在 `problems` 里（例如「检查点未签名」「有导入事件」），它们不构成失败。
---

## 5. 接入你自己的系统

前提只有一条：**事件必须经 `EventStore` 写**。链是在写锁内接上的，绕过它直接 `appendFile` 就是断链（后续追加会被拒绝，校验会指出断点）。

### 5.1 最小可用：写入事件

```js
import { EventStore } from "./src/event-log.mjs";

const store = new EventStore({
  eventPath: "./audit/events.jsonl",      // 事件流：一行一个 JSON 对象
  projectionPath: "./audit/projection.json",
});

await store.append({
  type: "your.action_completed",          // 事件类型，点分小写
  source: "your-system",                  // 谁写的：便于事后按来源过滤
  sessionId: "s-1",                       // 关联 ID：把一次运行的事件串起来
  runId: "r-1",
  payload: { what: "某个动作的结果摘要" },
});
```

不需要手工填的字段：`id`（UUID）、`timestamp`（ISO 8601 UTC）、`schemaVersion`、以及整个 `chain` 块 —— 它们由事件流在写入时补全。写盘后一条事件长这样（实测）：

```json
{
  "schemaVersion": "2.0",
  "id": "5f1c2e3a-0000-4000-8000-000000000001",
  "timestamp": "2026-01-01T00:00:00.000Z",
  "runId": "r-1",
  "sessionId": "s-1",
  "source": "your-system",
  "type": "your.action_completed",
  "payload": { "what": "某个动作的结果摘要" },
  "meta": {},
  "chain": {
    "seq": 1,
    "prev": "genesis",
    "algorithm": "sha256",
    "hash": "…"
  }
}
```

几条来自实现本身的约束：

- **一条一行。** 不要美化打印事件流 —— 那是写盘格式，不是给人读的文件；要给人读的视图由投影与报告负责。
- **`payload` 里不要放原文敏感值。** 完整产品的做法值得照抄：涉及 URL 的动作记 `origin` + 方法 + 路径的 SHA-256；涉及内容写入的记字节数与 SHA-256。审计流本身应该尽量不含敏感内容，否则脱敏就变成了唯一的防线。
- **关联 ID 建议始终带上。** 网关对工具动作强制要求 `sessionId` 与 `runId`；事件流层面允许为空，但少了它们，事后很难把同一次运行的记录拼起来。

### 5.2 让它可被验证：签名检查点

```js
import { readFileSync } from "node:fs";
import { ensureAuditKey, appendCheckpoint } from "./src/audit-chain.mjs";

// 首次运行会生成 ./audit/audit-key.pem（已存在则复用）
const ensured = await ensureAuditKey("./audit", { environment: {} });

// 密钥通过环境变量交给签名逻辑。注意交的是 PEM 文本，不是 KeyObject（见下）
const environment = {};
environment[ensured.keyEnv] = readFileSync(ensured.path, "utf8");   // 默认变量名 DEEPCOLLAB_AUDIT_KEY

const checkpoint = await appendCheckpoint(store, { reason: "manual", environment });
// checkpoint.signed === true, checkpoint.keyId === "ed25519:…"
```

**一个实测踩过的坑：** 环境变量的值必须是可解析的**密钥材料**（PEM 文本，或 base64 / hex 编码的 PKCS#8 DER）。把 `ensureAuditKey` 返回的 `KeyObject` 直接赋进去，密钥解析会失败，结果是检查点**照常写入但没有签名** —— 不报错、不留断链，只有在校验时才以 `AUDIT_CHECKPOINT_UNSIGNED` 显形。这是刻意的设计（审计流不该因为签名不可用就停止记录），但很容易被忽略。

取可信时间戳需要联网，默认时间源是 `freetsa.org`。要给检查点带上第三方时间证人，需要在 `appendCheckpoint` 里传入运行时装配好的网络客户端与 TSA 配置；不可达时检查点照常写入，失败原因会落盘并在校验时显形。

**一个建议（属于运维，不属于代码）：** 默认密钥文件与事件流在同一个工作区。要做到「防伪造」而不是「防误改」，请把私钥移到工作区之外，并把公钥带外固定后再交给复核方。

### 5.3 让预算成为硬约束

第三个闸门是 RoE 预算，实现在 `src/budget.mjs`：`createRequestBudget({ maxRequestsPerSession, requestsPerMinute })` 返回一个预算对象，网关在**执行之前**先按动作声明的开销预扣（`assertAffordable`），扣不满就直接拒绝并写 `tool.action_blocked`（`TOOL_BUDGET_EXCEEDED`），而不是执行完再统计。字段名与 `examples/demo-config.example.json` 里的 `roe` 一致 —— Demo 第 2 步撞的就是这个上限。

这正是「预算」与「配额提醒」的区别：前者是执行路径上的一个判断，后者是一句建议。
---

## 6. 复核别人交给你的信任包

信任包是**完整产品**导出的一整套证明材料（事件流副本、脱敏副本、清单、签名、时间戳令牌、包内校验和）。本仓库不生成它，只**复核**它 —— 这正是开源这一半的意义：生成方与复核方不应是同一份代码的信徒。

```bash
node tools/verify.mjs --dir <信任包目录>
```

常见用法：

```bash
# 带外固定了公钥与清单指纹，做到「连包带清单一起换掉也能发现」
node tools/verify.mjs --dir ./bundle \
  --expect-signing-key ed25519:0123456789abcdef \
  --expect-bundle-digest <64 位十六进制清单指纹>

# 机器可读，便于接进流水线
node tools/verify.mjs --dir ./bundle --json
```

它逐项检查、逐项给结论，每一条都带稳定错误码。**不给 `--expect-bundle-digest` 时会有一条警告**（`BUNDLE_DIGEST_UNPINNED`）：包能自证「内部一致」，但无法证明「它就是你收到的那一份」。包内文件本身有 `SHA256SUMS.txt` 覆盖，那防的是传输损坏与局部改动；防「整包替换」靠的是带外固定的指纹。

---

## 7. 常见报错与排查

所有结论都带稳定错误码。先看 `ok` 是不是 `false`（`warn` 不构成失败），再看具体码。

### 7.1 哈希链相关

| 码 / 输出 | 含义 | 怎么办 |
| --- | --- | --- |
| `AUDIT_CHAIN_HASH_MISMATCH` 事件内容哈希不匹配（第 N 条，type=…） | 第 N 条的内容与它写盘时的哈希对不上 —— 被改过 | 定位到那一条，与来源系统核对。**不要**手工改回内容：改回去也不会恢复原哈希 |
| `AUDIT_CHAIN_PREV_MISMATCH` 前序哈希不匹配 | 第 N 条的 `prev` 与第 N-1 条的 `hash` 不接 | 通常是中间被删除或调序 |
| `AUDIT_CHAIN_GAP` 链序号不连续：期望 X，实际 Y | 有条目被删掉 | 结合上一条一起看，断点就在中间 |
| `AUDIT_CHAIN_TAIL_INVALID` 最后一行不是完整 JSON | 写入被中断，尾部留了半行 | 这是**拒绝追加**的保护：事件流不会把断链继续接上。截掉那半行后再写，或从备份恢复 |
| `AUDIT_CHAIN_BROKEN` 存在链式事件，但最后一条不在链上 | 有人在链建立之后追加了未接链的事件 | 同上：先定位，再决定截断还是恢复 |
| `AUDIT_IMPORTED_EVENTS`（**警告**） | 流里有通过导入通道写入的历史事件。它们正常接链，链**无法**分辨真伪 | 不是失败。这类事件引用前请人工确认来源 —— 校验器会把导入来源一并列出 |

### 7.2 签名与密钥相关

| 码 / 输出 | 含义 | 怎么办 |
| --- | --- | --- |
| `AUDIT_CHECKPOINT_UNSIGNED` 检查点未签名（原因） | 签名时密钥不可用。常见原因就是 `AUDIT_KEY_INVALID` | 检查环境变量里放的是不是**密钥材料**（PEM 文本 / base64 / hex 的 PKCS#8 DER），而不是别的对象 |
| `AUDIT_KEY_INVALID` | 密钥解析失败 | 同上。另注意：密钥文件路径与变量名是否对应 |
| `AUDIT_SIGNATURE_UNVERIFIABLE` 无法获得公钥，签名未校验 | 事件流里既没有内嵌公钥，也没有外部固定公钥 | 用 `--pubkey` 从外部固定，或要求来源方在检查点里带上公钥 |
| `AUDIT_SIGNATURE_INVALID` 签名校验失败 | 检查点载荷被改，或不是这把钥匙签的 | 按篡改处理 |
| `AUDIT_KEY_MISMATCH` 检查点使用了 X，与固定公钥 Y 不一致 | 你固定的公钥与签署者不符 | 先确认**你手上的公钥**是不是那条可信渠道给的；如果它是对的，这份记录就不是你预期的那一方签的 |
| `AUDIT_CHECKPOINT_CHAIN_BROKEN` 检查点前序引用不匹配 | 检查点被删、被换或被事后补写 | 按篡改处理 |
| `AUDIT_CHECKPOINT_COVERAGE_MISMATCH` 检查点声明的覆盖链头与链上实际内容不一致 | 检查点声称覆盖第 N 条，但那一条的内容对不上 | 按篡改处理 |
| 结论里有 `提示：使用事件流内嵌公钥校验…` | **不是错误，是提醒** | 当前「签名有效」仅指与内嵌公钥匹配。要来源含义，必须带外固定公钥 |

### 7.3 可信时间戳相关

| 码 / 输出 | 含义 | 怎么办 |
| --- | --- | --- |
| `可信时间戳：0 个（…无时间戳检查点 N）` | 这些检查点从来没取过时间戳 | 正常情况（离线环境）。要第三方时间证人，需要在联网环境签检查点 |
| `AUDIT_TIMESTAMP_MISSING`（**警告**）检查点未取得可信时间戳（原因） | 取过但没成功，原因已落盘 | 常见原因 `TS_NETWORK_UNAVAILABLE`（运行时没有网络客户端）与网络/超时。**不构成失败**，检查点与签名仍然有效 |
| `AUDIT_TIMESTAMP_INVALID`（**错误**）可信时间戳校验失败：… | 令牌存在但验不过（被改动、与载荷不匹配、或 TSA 证书不符） | 按篡改或配置错误处理。这一条**会让链判为不通过** |
| `TS_LOCAL_VERIFY_FAILED` / `TS_FAILED` | 令牌本地校验未通过 / 请求失败 | 看随附的 reason 字段 |

### 7.4 命令行与用法相关

| 现象 | 原因 | 怎么办 |
| --- | --- | --- |
| `node tools/verify.mjs --dir .` 报 `PACKAGE_SUMS_MISSING` + `BUNDLE_MISSING`（退出码 2） | 你在用**信任包校验器**跑一份**裸事件流** | 改用 `node tools/verify-stream.mjs <事件流路径>`。这两条命令职责不同，见根 README 的“三个可运行入口” |
| `SyntaxError` / 特性不支持 | Node 版本低于 20 | 升级到 Node >= 20 |
| 校验器报读不到文件 | 路径不对，或路径不是本地路径 | 本仓库只接受本地文件路径：UNC 与网络共享路径会被直接拒绝（这是刻意的） |
| Demo 跑完什么都没留下 | Demo 默认跑在临时目录 | 这是刻意的。要留证据就指定目录：`node examples/run-demo.mjs ./demo-workspace` |

### 7.5 先做这三件事

排查任何一个「结论不对」的问题，按这个顺序走，能省掉大部分来回：

1. **看 `ok`，别看有没有 `problems`。** 警告也会进 `problems`。
2. **看有没有 `提示：使用事件流内嵌公钥校验`。** 有的话，你手上的「签名有效」不含来源含义。
3. **看退出码。** `0` 通过、`2` 完整性问题、`1` 用法或读取错误 —— `1` 与 `2` 是两回事，别把用法错误当成数据被篡改。

---

## 8. 退出码速查

| 退出码 | 含义 |
| --- | --- |
| `0` | 通过（可能有警告，例如未签名检查点、导入事件、无时间戳） |
| `2` | 存在完整性问题（哈希链断裂、签名不符、固定的公钥/指纹不匹配、时间戳验不过） |
| `1` | 用法错误或读取错误（路径不对、参数不认识、Node 版本过低） |

---

## 9. 这套东西不承诺什么

部署与验证跑通之后，最容易发生的误读是把「链完整、签名有效」当成「这份记录是真的、这些行为是合法的」。它不是这个意思：

- 它证明**记录自某个时刻起没有被改动**，不证明记录里的行为正当、合法或经过授权；
- 它证明**由某把私钥签署**，不证明签署者是谁 —— 除非公钥是你另外一条渠道拿到的并当场固定；
- 它证明**链头在某个第三方时刻之前存在**，不证明被覆盖的那些事件发生在那个时刻。

只在你被书面授权的目标上使用本项目的任何产出。
