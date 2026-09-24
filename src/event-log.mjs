import { appendFile, mkdir, open, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { assertLocalPath } from './local-paths.mjs';
import { appendCheckpoint, chainEvents, readChainHead } from './audit-chain.mjs';
import { EVENT_SCHEMA_VERSION, SHARED_EVENT_SCHEMA_VERSION, chainOf, encodeEvent, normalizeLegacyEvent, serializeSharedEvent } from './event-codec.mjs';

// 编码层的既有导入路径保持不变：events.mjs 继续对外暴露这几个符号。
export { EVENT_SCHEMA_VERSION, SHARED_EVENT_SCHEMA_VERSION, normalizeLegacyEvent, serializeSharedEvent, encodeEvent };

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// 抢锁失败**未必**长着 EEXIST 的样子。Windows（尤其是 FAT32/U 盘，或杀软正在扫
// 刚创建的文件）上，「另一个进程刚 unlink、我立刻 CREATE_NEW」这条路会返回
// EPERM / EACCES / EBUSY —— 和 EEXIST 一样都是「现在不行，马上再试就好」。
// 原实现只重试 EEXIST，其余一律立刻抛出，于是**普通的并发竞争会以一行原始 errno
// 打断整轮会话**（实测：三个 TUI 共用一个工作区时跑到一半报
// EPERM: operation not permitted, open '...\events.jsonl.lock'）。
// 真正不可恢复的（只读卷 EROFS、空间耗尽 ENOSPC）仍旧立刻抛出，重试没有意义。
const TRANSIENT_LOCK_CODES = new Set(['EEXIST', 'EPERM', 'EACCES', 'EBUSY', 'EAGAIN']);
export function isTransientLockError(code) {
  return TRANSIENT_LOCK_CODES.has(code);
}

function validateEventInput(input) {
  if (!input?.type || typeof input.type !== 'string') throw new Error('事件 type 必须是非空字符串');
  if (input.payload !== undefined && (!input.payload || typeof input.payload !== 'object' || Array.isArray(input.payload))) {
    throw new Error('事件 payload 必须是对象');
  }
}

async function readEventFile(path) {
  let text = '';
  try {
    text = await readFile(assertLocalPath(path), 'utf8');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const events = [];
  const broken = [];
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    try {
      events.push(normalizeLegacyEvent(JSON.parse(line)));
    } catch (error) {
      broken.push({ line: index + 1, preview: line.slice(0, 160), error: error.message });
    }
  }
  return { events, broken };
}

function legacyProjection(context) {
  return {
    schema_version: SHARED_EVENT_SCHEMA_VERSION,
    task: context.task,
    phase: context.phase,
    strategy: context.strategy,
    analysis: context.strategy,
    executor_status: context.phase,
    last_result: context.lastResult,
    run_id: context.runId,
    session_id: context.sessionId,
    history: context.history.map(item => ({
      role: item.role === 'advisor' ? 'deepseek' : 'deepcode',
      content: item.content,
      time: item.timestamp,
    })),
    created: context.startedAt,
    projected_at: context.projectedAt,
    projected_from: context.projectedFrom,
  };
}

export class EventStore {
  constructor({ eventPath, projectionPath, compatibilityProjectionPath = null, writeFormat = 'native-v2', lockTimeoutMs = 3000, staleLockMs = 30000, reducers = [],
    chainEnabled = true, auditCheckpointEvery = 0, auditKeyEnv = 'DEEPCOLLAB_AUDIT_KEY', auditEnvironment = process.env,
    auditTimestamp = null, auditSignal = null }) {
    this.eventPath = assertLocalPath(eventPath);
    this.projectionPath = assertLocalPath(projectionPath);
    this.compatibilityProjectionPath = compatibilityProjectionPath ? assertLocalPath(compatibilityProjectionPath) : null;
    if (!['native-v2', 'shared-v1'].includes(writeFormat)) throw new Error('事件写入格式必须为 native-v2 或 shared-v1');
    this.writeFormat = writeFormat;
    this.lockPath = `${eventPath}.lock`;
    this.lockTimeoutMs = lockTimeoutMs;
    this.staleLockMs = staleLockMs;
    this.reducers = reducers;
    // 事件级哈希链：默认开启。链只追加，不改写历史（历史内容用创世锚点一次性封入）。
    this.chainEnabled = chainEnabled !== false;
    // 每 N 条链式事件自动签一个检查点；0 表示只允许手动签。EventStore 默认关闭，
    // 由 createRuntime 按 config.audit.checkpointEvery 打开。
    this.auditCheckpointEvery = Number.isSafeInteger(auditCheckpointEvery) && auditCheckpointEvery >= 10 ? auditCheckpointEvery : 0;
    this.auditKeyEnv = auditKeyEnv || 'DEEPCOLLAB_AUDIT_KEY';
    this.auditEnvironment = auditEnvironment || process.env;
    // 可信时间戳配置与网络客户端：createRuntime 在装配 NetworkClient 之后回填 auditNetwork。
    this.auditTimestamp = auditTimestamp || null;
    this.auditNetwork = null;
    this.auditSignal = auditSignal || null;
    this.head = null;
    this.headSize = -1;
    this.checkpointInFlight = false;
    this.lastCheckpointError = null;
  }

  // 链头缓存：只在文件大小变化时才重新读尾部，避免每次追加都全量解析事件流。
  async resolveHead() {
    const info = await stat(this.eventPath).catch(() => null);
    const size = info ? info.size : 0;
    if (this.head && size === this.headSize) return this.head;
    const head = await readChainHead(this.eventPath);
    this.head = head;
    this.headSize = size;
    return head;
  }

  async chainFor(events) {
    if (!this.chainEnabled) return events;
    const head = await this.resolveHead();
    const chained = chainEvents(events, head);
    const last = chained[chained.length - 1];
    if (last?.chain) { this.head = { seq: last.chain.seq, hash: last.chain.hash, anchor: null }; this.headSize = -1; }
    return chained;
  }

  // 自动检查点在锁外执行：appendCheckpoint 自己会再取一次写锁。
  async maybeCheckpoint() {
    if (!this.chainEnabled || !this.auditCheckpointEvery || this.checkpointInFlight) return null;
    if (!this.head?.seq || this.head.seq % this.auditCheckpointEvery !== 0) return null;
    this.checkpointInFlight = true;
    try {
      return await appendCheckpoint(this, { reason: 'automatic', keyEnv: this.auditKeyEnv, environment: this.auditEnvironment,
        network: this.auditNetwork, timestamp: this.auditTimestamp });
    } catch (error) {
      this.lastCheckpointError = error.message;
      return null;
    } finally {
      this.checkpointInFlight = false;
    }
  }

  async ensure() {
    await mkdir(dirname(this.eventPath), { recursive: true });
    await mkdir(dirname(this.projectionPath), { recursive: true });
    if (this.compatibilityProjectionPath) await mkdir(dirname(this.compatibilityProjectionPath), { recursive: true });
  }

  async withLock(fn) {
    const deadline = Date.now() + this.lockTimeoutMs;
    let handle;
    while (!handle) {
      try {
        handle = await open(this.lockPath, 'wx');
      } catch (error) {
        if (!isTransientLockError(error.code)) throw error;
        // Age alone cannot establish that another process no longer owns a lock.
        if (Date.now() >= deadline) {
          throw Object.assign(new Error(
            '无法获取事件流写锁：' + this.lockPath + '（最后一次失败 ' + error.code + '）。'
            + '最常见的原因是另一个 dcc 正在使用同一个工作区；'
            + '确认其它会话都已退出后，若该 .lock 文件仍然存在，删掉它即可恢复。'),
          { code: 'EVENT_LOCK_TIMEOUT', lastErrorCode: error.code });
        }
        // 退避 + 抖动：多个会话同时重试时不要整齐划一地撞在一起。
        await sleep(20 + Math.floor(Math.random() * 40));
      }
    }
    try {
      return await fn();
    } finally {
      await handle.close();
      await unlink(this.lockPath).catch(() => {});
    }
  }

  make(input) {
    validateEventInput(input);
    return {
      schemaVersion: EVENT_SCHEMA_VERSION,
      id: input.id || randomUUID(),
      timestamp: input.timestamp || new Date().toISOString(),
      runId: input.runId ?? null,
      sessionId: input.sessionId ?? null,
      source: input.source || 'cli',
      type: input.type,
      payload: input.payload || {},
      meta: input.meta || {},
    };
  }

  async append(input) {
    const [event] = await this.appendMany([input]);
    return event;
  }

  async appendMany(inputs) {
    const events = inputs.map((input) => this.make(input));
    if (events.length === 0) return [];
    await this.ensure();
    // 链头解析与写入必须在同一把锁内，否则并发进程会算出同一个 seq。
    const written = await this.withLock(async () => {
      const chained = await this.chainFor(events);
      await appendFile(this.eventPath, `${chained.map((event) => encodeEvent(event, this.writeFormat)).join('\n')}\n`, 'utf8');
      return chained;
    });
    await this.maybeCheckpoint();
    return written;
  }

  // 持锁执行「读 → 算 → 写」整体。
  //
  // 为什么必须是整体：检查点的「前序引用」要靠读事件流才能算出来。
  // 读放在锁外的话，N 个进程会各自读到同一个前序，再排队写下去，
  // 于是 N 个检查点的前序全指向同一处 —— 事后校验报「检查点序列可能被删改」。
  // 也就是说：并发用一次，就被自己的审计链判成篡改。
  //
  // 签名与可信时间戳也在锁内：时间戳锚定的是含前序引用的那份载荷，
  // 前序一变，时间戳就对着另一份数据了。
  async appendDerived(build) {
    await this.ensure();
    return this.withLock(async () => {
      const snapshot = await readEventFile(this.eventPath);
      const input = await build(snapshot);
      if (!input) return null;
      const chained = await this.chainFor([this.make(input)]);
      await appendFile(this.eventPath, `${encodeEvent(chained[0], this.writeFormat)}
`, 'utf8');
      return chained[0];
    });
  }
  async read() {
    return readEventFile(this.eventPath);
  }

  async importFile(sourcePath) {
    const source = assertLocalPath(sourcePath);
    if (source === this.eventPath) return { source, imported: 0, duplicates: 0, broken: [] };
    const incoming = await readEventFile(source);
    if (incoming.broken.length) {
      const error = new Error(`导入源包含 ${incoming.broken.length} 个损坏事件，已拒绝导入`);
      error.code = 'AUDIT_IMPORT_INVALID';
      throw error;
    }
    await this.ensure();
    let imported = 0;
    let duplicates = 0;
    await this.withLock(async () => {
      const current = await readEventFile(this.eventPath);
      if (current.broken.length) throw Object.assign(new Error('目标事件流含损坏行，已拒绝导入'), { code: 'AUDIT_CORRUPT' });
      const ids = new Set(current.events.map(event => event.id));
      const fresh = [];
      for (const event of incoming.events) {
        if (ids.has(event.id)) { duplicates++; continue; }
        ids.add(event.id);
        // 导入的事件会被正常接链 —— 光看链是分辨不出它不是本机产生的。
        // 所以导入时必须盖一个改不掉的戳：它在 meta 里，因此被哈希覆盖；之后想抹掉就会断链。
        const chain = chainOf(event);
        const rest = { ...event };
        delete rest.chain;
        const prior = rest.meta && rest.meta.imported ? rest.meta.imported : null;
        fresh.push({ ...rest, meta: {
          ...(rest.meta || {}),
          imported: {
            source: String(source).replace(/\\/g, '/'),
            at: new Date().toISOString(),
            originalChain: chain || null,
            ...(prior ? { previous: prior } : {}),
          },
        } });
      }
      if (fresh.length) {
        const chained = await this.chainFor(fresh);
        await appendFile(this.eventPath, `${chained.map(event => encodeEvent(event, this.writeFormat)).join('\n')}\n`, 'utf8');
      }
      imported = fresh.length;
    });
    return { source, imported, duplicates, broken: [] };
  }

  project(events) {
    const context = {
      schemaVersion: EVENT_SCHEMA_VERSION,
      task: '',
      phase: 'idle',
      strategy: '',
      lastResult: '',
      runId: null,
      sessionId: null,
      history: [],
      workLog: [],
      startedAt: null,
      projectedAt: new Date().toISOString(),
      projectedFrom: this.eventPath,
    };
    for (const event of events) {
      // Late replies from an older session must not contaminate the active one.
      if (event.type !== 'session.started' && event.sessionId && event.sessionId !== context.sessionId) continue;
      context.runId = event.runId ?? context.runId;
      switch (event.type) {
        case 'session.started':
          context.task = String(event.payload.task || '');
          context.phase = 'active';
          context.strategy = '';
          context.lastResult = '';
          context.runId = event.runId;
          context.sessionId = event.sessionId;
          context.startedAt = event.timestamp;
          context.history = [];
          context.workLog = [];
          break;
        case 'consult.requested':
        case 'bridge.consult':
          context.phase = 'consulting';
          context.history.push({ role: 'user', content: String(event.payload.content || ''), timestamp: event.timestamp });
          break;
        case 'advisor.responded':
        case 'deepseek.strategy':
          context.phase = 'ready';
          context.strategy = String(event.payload.content || '');
          context.history.push({ role: 'advisor', content: context.strategy, reasoning: String(event.payload.reasoning || ''), timestamp: event.timestamp });
          break;
        case 'advisor.interrupted':
          context.history.push({ role: 'advisor', content: String(event.payload.content || ''), reasoning: String(event.payload.reasoning || ''), timestamp: event.timestamp, partial: true });
          break;
        case 'executor.reported':
        case 'deepcode.report':
          context.phase = 'reporting';
          context.lastResult = String(event.payload.content || '');
          context.history.push({ role: 'executor', content: context.lastResult, timestamp: event.timestamp });
          break;
        case 'provider.failed':
          context.phase = event.payload.code === 'AGENT_PAUSED' ? 'paused' : event.payload.blocked ? 'blocked' : 'failed';
          break;
        case 'agent.progress':
          context.workLog.push({
            layer: String(event.payload.layer || '进度'),
            content: String(event.payload.content || ''),
            status: String(event.payload.status || 'running'),
            timestamp: event.timestamp,
          });
          break;
        case 'session.ended':
        case 'bridge.reset':
          context.task = '';
          context.phase = 'idle';
          context.strategy = '';
          context.lastResult = '';
          context.runId = null;
          context.sessionId = null;
          context.startedAt = null;
          context.history = [];
          context.workLog = [];
          break;
        default:
          break;
      }
      for (const reducer of this.reducers) reducer(context, event);
    }
    return context;
  }

  async rebuild() {
    await this.ensure();
    return this.withLock(async () => {
      const { events, broken } = await this.read();
      const context = this.project(events);
      const temp = `${this.projectionPath}.${process.pid}.${randomUUID()}.tmp`;
      const compatibilityTemp = this.compatibilityProjectionPath
        ? `${this.compatibilityProjectionPath}.${process.pid}.${randomUUID()}.tmp` : null;
      await writeFile(temp, `${JSON.stringify(context, null, 2)}\n`, 'utf8');
      if (compatibilityTemp) await writeFile(compatibilityTemp, `${JSON.stringify(legacyProjection(context), null, 2)}\n`, 'utf8');
      await rename(temp, this.projectionPath);
      if (compatibilityTemp) await rename(compatibilityTemp, this.compatibilityProjectionPath);
      return { context, broken };
    });
  }
}
