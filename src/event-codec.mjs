import { randomUUID } from 'node:crypto';

// 事件在磁盘上的两种编码（native-v2 原生对象 / shared-v1 共享字段名）以及它们之间的往返。
// 单独成模块是为了打断 events.mjs 与 audit-chain.mjs 的循环依赖：
// 两边都需要"把磁盘行还原成事件对象"的能力，而这件事只该有一份实现。

export const EVENT_SCHEMA_VERSION = '2.0';
export const SHARED_EVENT_SCHEMA_VERSION = '1.0';

// shared-v1 没有顶层扩展位，链信息写在 meta.chain；native-v2 直接放顶层。
export function chainOf(raw) {
  if (raw && typeof raw.chain === 'object' && raw.chain) return raw.chain;
  if (raw && raw.meta && typeof raw.meta.chain === 'object' && raw.meta.chain) return raw.meta.chain;
  return null;
}

export function normalizeLegacyEvent(raw) {
  if (!raw || typeof raw !== 'object') throw new Error('事件必须是对象');
  if (raw.type && raw.id && raw.timestamp) {
    const chain = chainOf(raw);
    return chain && !raw.chain ? { ...raw, chain } : raw;
  }
  const event = {
    schemaVersion: EVENT_SCHEMA_VERSION,
    id: raw.event_id || randomUUID(),
    timestamp: raw.ts || new Date().toISOString(),
    runId: raw.run_id ?? null,
    sessionId: raw.session_id === 'none' ? null : (raw.session_id ?? null),
    source: raw.source || 'legacy',
    type: raw.event_type || 'legacy.unknown',
    payload: raw.payload && typeof raw.payload === 'object' ? raw.payload : {},
    meta: { ...(raw.meta || {}), importedFromSchema: raw.schema_version || 'unknown' },
  };
  const chain = chainOf(raw);
  if (chain) event.chain = chain;
  return event;
}

export function serializeSharedEvent(event) {
  return {
    schema_version: SHARED_EVENT_SCHEMA_VERSION,
    event_id: event.id,
    ts: event.timestamp,
    run_id: event.runId ?? null,
    session_id: event.sessionId ?? 'none',
    source: event.source,
    event_type: event.type,
    payload: event.payload || {},
    meta: {
      ...(event.meta || {}),
      internal_schema: event.schemaVersion || EVENT_SCHEMA_VERSION,
      ...(event.chain ? { chain: event.chain } : {}),
    },
  };
}

export function encodeEvent(event, format) {
  return JSON.stringify(format === 'shared-v1' ? serializeSharedEvent(event) : event);
}
