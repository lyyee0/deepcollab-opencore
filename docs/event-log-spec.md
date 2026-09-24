# 事件流格式标准（Event Log Format）

本文规定 DeepCollab 事件流的**磁盘格式**。凡是按本格式写入的流，都能被本仓库的
`tools/verify-stream.mjs` 校验；凡是改动过任意一个字节的流，都会被它指出来。

## 1. 文件形态

- 一行一条 JSON 对象（JSONL），UTF-8 编码，行尾 `\n`，最后一行**必须**以换行结束。
- 追加写：只允许在文件末尾追加，不允许改写既有行。
- 空行被忽略；无法解析的行被记为「损坏行」，不静默跳过。
- 与流同目录的 `context.json` 之类是**可重建投影**，不是第二条事实来源。删掉它不影响任何校验。

## 2. 事件对象的字段

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `schemaVersion` | string | 本编码的版本，当前 `"2.0"`（下称 native-v2）。 |
| `id` | string | 事件唯一 ID。建议 UUID。 |
| `timestamp` | string | ISO 8601（UTC，毫秒）。**本机时钟**，可被改；它的可信度由第 6 节的检查点补足。 |
| `runId` | string \| null | 一次运行的 ID。同一会话可以有多轮运行。 |
| `sessionId` | string \| null | 任务会话 ID。三件关联键中最外层的一个。 |
| `source` | string | 写入者，例如 `cli` / `orchestrator` / `tool-gateway`。 |
| `type` | string | 事件类型，形如 `tool.action_requested`。见第 8 节。 |
| `payload` | object | 类型各自定义。**它不参与「哪些字段被哈希」的自由发挥**：整个对象都在哈希里。 |
| `meta` | object | 扩展位。编码层自己写入的键（见第 4 节）不参与哈希。 |
| `chain` | object | 链信息，见第 5 节。**未建链的历史事件没有这个字段。** |

三件关联键的分工是固定的：`sessionId` 标识任务，`runId` 标识这一轮运行，
`actionId`（在 `payload` 里）标识一次**物理动作**。供应商返回的 `tool_call_id` 只作为
`modelToolCallId` 保存，**不能**替代网关生成的动作 ID —— 否则模型就能自己指定动作的身份。

## 3. 第二种编码：shared-v1

为了兼容早期协议，磁盘上还有第二种写法：

```json
{ "schema_version": "1.0", "event_id": "…", "ts": "…", "run_id": null, "session_id": "none",
  "source": "cli", "event_type": "session.started", "payload": {}, "meta": { "chain": { } } }
```

往返规则（`src/event-codec.mjs` 是唯一实现）：

- `shared-v1` 没有顶层扩展位，链信息写在 `meta.chain`；读进来时提到顶层 `chain`。
- `session_id: "none"` 读作 `null`。
- 顶层已有 `type` / `id` / `timestamp` 的行按 native-v2 读，**不做二次包装**。
- 编码层自己写入的 `meta` 键在算哈希时被排除：`internal_schema`、`importedFromSchema`、
  `imported_chain`、`chain`。不排除它们，同一行读回来 `meta` 就变了，链会整体误报断裂。

## 4. 哈希覆盖的确切字段集合

「哪些字段被哈希」必须是封闭的一张表，不能靠约定。被哈希的**恰好**是这些（`eventHashInput()`）：

```
schemaVersion, id, timestamp, runId, sessionId, source, type, payload, meta(去掉编码层键),
seq, prev, genesis
```

**不参与**哈希的：`chain.hash`、`chain.algorithm`。

序列化用稳定形式：对象键按字典序递归排序，数组保持顺序（`src/canonical.mjs`）。
只有这样，同一个逻辑对象在任何进程、任何时刻才会得到同一串字节。

## 5. 链字段与创世锚点

```json
"chain": { "seq": 7, "prev": "<上一条的 hash>", "algorithm": "sha256", "hash": "<本条 hash>" }
```

- `seq`：从 1 开始的连续整数。**不连续即视为断裂**。
- `prev`：上一条的 `hash`；第一条是字符串 `"genesis"`。
- `hash` = `sha256(canonicalJson(eventHashInput(event, chain)))`，十六进制小写。
- `genesis`（可选）：只在**建链后的第一条**出现，把「建链之前就已经存在的历史内容」
  一次性封进一个全文件摘要 `{ events, bytes, sha256 }`。历史行不被改写，但从此不能再被改动而不被发现。

追加的失败姿态是 **fail closed**：如果文件最后一条非空行不在链上，而文件里又**存在**链式事件，
那说明链已断裂 —— 此时拒绝追加新事件，而不是把断裂的流接着往下写。
（最后一条不在链上、且全文件都没有链式事件，才是「尚未建链的历史流」，此时建创世锚点。）

## 6. 检查点事件

检查点是**一条普通事件**，`type` 为 `audit.checkpoint`：

```json
{ "type": "audit.checkpoint", "source": "audit-chain", "meta": { "noCheckpoint": true },
  "payload": {
    "checkpoint": { "version": 1,
      "covers": { "seq": 12, "hash": "<第 12 条的 hash>", "count": 12 },
      "at": "…", "key_id": "ed25519:…", "previous_checkpoint": "<上一个检查点的 covers.hash>" },
    "signature": "<base64(Ed25519(canonicalJson(checkpoint)))>",
    "signed": true, "public_key": "<SPKI base64>", "key_env": "DEEPCOLLAB_AUDIT_KEY",
    "reason": "manual", "unsigned_reason": null, "timestamp": { } } }
```

三个要点：

1. **被签名的是规范化后的 `checkpoint` 对象本身**，不是整条事件。
2. `previous_checkpoint` 指向上一个检查点的 `covers.hash`。因此**删掉中间某个检查点、
   换掉某个检查点、或改动链头，都会在下一跳暴露**。
3. 可信时间戳（RFC 3161）锚定的是**这份被签名的载荷的 SHA-256**，不是事件流文件。
   它证明的是「这个检查点在 TSA 签发时刻已经存在」，本机时钟改不掉它。
   TSA 不可达时检查点**照常写入**，但 `timestamp` 会带着失败原因落盘、校验时被标出来，
   不会假装成功。

## 7. 校验失败时能知道什么

`tools/verify-stream.mjs` 会逐条给出问题与**第几条**：

| 代码 | 含义 |
| --- | --- |
| `AUDIT_CHAIN_HASH_MISMATCH` | 某条事件的内容与它自己的 `hash` 对不上（内容被改过）。 |
| `AUDIT_CHAIN_PREV_MISMATCH` | 某条的 `prev` 不是上一条的 `hash`（中间被删过或插过）。 |
| `AUDIT_CHAIN_SEQ_GAP` | `seq` 不连续。 |
| `AUDIT_CHAIN_BROKEN` | 追加时发现最后一条不在链上（拒绝继续写）。 |
| `AUDIT_CHAIN_TAIL_INVALID` | 最后一行不是完整 JSON，通常是写入被中断。 |
| `ANCHOR_MISMATCH` | 创世锚点不匹配：建链前的历史内容被改过。 |

它**能**证明的：内容自写入以来没有被改动、没有删除、没有插入，且检查点由持有对应私钥的一方签署过。
它**不能**证明的：签署者是谁。默认密钥与事件流同处一个工作区，拿到磁盘的人可以把两样一起换掉。
要跨组织抵赖，必须把公钥**带外**固定，再用 `--pubkey` 校验。

## 8. 事件类型

`type` 是自由字符串，但建议保持 `域.动作` 的形态，便于按前缀聚合：

- 会话与轮次：`session.started` / `session.ended` / `turn.started` / `turn.completed`
- 动作生命周期：`tool.action_requested` → `tool.action_started` → `tool.action_completed` /
  `tool.action_failed` / `tool.action_interrupted` / `tool.action_blocked`
- 审计自身：`audit.checkpoint` / `audit.rotated`

动作事件的**顺序是约束，不是约定**：意图（requested）必须在效果发生之前落盘，
效果完成之后才能写 completed。中途进程被杀，流里就留下一条没有结局的 started —— 
那正是它该有的样子。

## 9. 版本演进

- 新增字段：默认向后兼容，但**加进 `eventHashInput()` 的字段是破坏性变更**，
  因为历史行没有它，重算哈希会对不上。这类改动必须同时提升 `schemaVersion`。
- 新旧两种编码的读写由一个模块负责（`src/event-codec.mjs`），不允许各处自己解析磁盘行。
