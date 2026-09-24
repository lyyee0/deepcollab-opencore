// Tool Gateway —— 唯一动作入口的引用实现。
//
// 这个文件回答的问题是：**怎么保证模型发出的每一个动作都留下证据，且它想做的和它做过的是同一件事。**
// 它不回答「怎么去打一个目标」—— 扫描器、认证会话、定向探针的适配器不在本发布件里，这是设计不是遗漏。
// 下面配的适配器都是纯本地的示例，只用来把机制跑起来给人看。
//
// 五道处理，顺序不能变：
//   1. 形状检查 —— 请求只能有 { tool, arguments, modelToolCallId } 三个键，多一个就拒。
//      模型无法通过加字段的方式把「命令」「argv」「环境变量」透传进来。
//   2. 注册表 + 角色 —— 未注册的工具、当前角色无权的工具，直接拒。
//   3. 参数复验 —— 由**适配器自己**再验一遍。模型侧校验过不算数。
//   4. RoE 预算预扣 —— 扣不动就不执行。
//   5. 先审计后执行 —— 意图先落盘，效果才允许发生。
//
// 无论在哪一步被拒，都会写一条事件：一份只记录「成功」的日志，无法回答「它到底试过什么」。

import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { sanitizeValue } from './redact.mjs';
import { createRequestBudget } from './budget.mjs';

// 关联键的形状是硬性的：它进事件流、进哈希链，形状不对就没法关联。
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const TOOL_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,79}$/;

const gatewayError = (code, message) => Object.assign(new Error(message), { code });

function assertCorrelation(context) {
  if (!ID.test(context?.sessionId || '')) throw gatewayError('GATEWAY_SESSION_REQUIRED', '统一执行入口要求有效 sessionId');
  if (!ID.test(context?.runId || '')) throw gatewayError('GATEWAY_RUN_REQUIRED', '统一执行入口要求有效 runId');
}

// 只认这三个键。多一个就拒 —— 这是「模型不能自己拼一条命令出来」的第一道保证。
function normalizeRequest(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) throw gatewayError('GATEWAY_REQUEST_INVALID', 'ActionRequest 必须是对象');
  const allowed = new Set(['tool', 'arguments', 'modelToolCallId']);
  if (Object.keys(request).some(key => !allowed.has(key))) throw gatewayError('GATEWAY_FIELD_DENIED', 'ActionRequest 包含未许可字段');
  if (!TOOL_NAME.test(request.tool || '')) throw gatewayError('GATEWAY_TOOL_INVALID', '工具名称无效');
  if (!request.arguments || typeof request.arguments !== 'object' || Array.isArray(request.arguments)) throw gatewayError('GATEWAY_ARGUMENTS_INVALID', '工具参数必须是对象');
  if (request.modelToolCallId !== undefined && !ID.test(request.modelToolCallId)) throw gatewayError('GATEWAY_TOOL_CALL_ID_INVALID', '模型工具调用 ID 无效');
  return { tool: request.tool, arguments: structuredClone(request.arguments), modelToolCallId: request.modelToolCallId || null };
}

export class ToolGateway {
  constructor({ store, budget = null }) {
    this.store = store;
    this.budget = budget;
    this.adapters = new Map();
  }

  // 适配器注册对象的字段是封闭的：name / roles / risk / effects / requestCost /
  // validate / audit / execute / auditResult。允许自由加字段的话，「这个工具能做什么」
  // 就不再是一张可以被审阅的表。
  register(adapter) {
    if (!adapter || !TOOL_NAME.test(adapter.name || '')) throw gatewayError('GATEWAY_ADAPTER_INVALID', '适配器名称无效');
    if (this.adapters.has(adapter.name)) throw gatewayError('GATEWAY_ADAPTER_DUPLICATE', '适配器重复注册: ' + adapter.name);
    if (typeof adapter.validate !== 'function' || typeof adapter.execute !== 'function') throw gatewayError('GATEWAY_ADAPTER_INVALID', '适配器必须提供 validate 与 execute');
    this.adapters.set(adapter.name, Object.freeze({ ...adapter }));
  }

  list(roleId) {
    return [...this.adapters.values()].filter(adapter => !adapter.roles || adapter.roles.includes(roleId))
      .map(adapter => ({ name: adapter.name, risk: adapter.risk || 'local', effects: adapter.effects || [] }));
  }

  async execute(rawRequest, context) {
    assertCorrelation(context);
    const actionId = randomUUID();
    const base = { source: 'tool-gateway', sessionId: context.sessionId, runId: context.runId };
    let request;
    try { request = normalizeRequest(rawRequest); }
    catch (error) {
      await this.store.append({ ...base, type: 'tool.action_blocked', payload: {
        action_id: actionId,
        model_tool_call_id: typeof rawRequest?.modelToolCallId === 'string' ? rawRequest.modelToolCallId : null,
        tool: typeof rawRequest?.tool === 'string' ? rawRequest.tool.slice(0, 80) : null,
        code: error.code || 'GATEWAY_REQUEST_INVALID',
      } });
      throw error;
    }

    const adapter = this.adapters.get(request.tool);
    const payloadBase = { action_id: actionId, model_tool_call_id: request.modelToolCallId, tool: request.tool };
    const adapterContext = { ...context, actionId, modelToolCallId: request.modelToolCallId };

    if (!adapter || (adapter.roles && !adapter.roles.includes(context.roleId))) {
      await this.store.append({ ...base, type: 'tool.action_blocked', payload: { ...payloadBase, code: 'TOOL_DENIED' } });
      throw gatewayError('TOOL_DENIED', '工具未注册或当前角色不允许');
    }

    let args;
    try { args = adapter.validate(request.arguments, adapterContext); }
    catch (error) {
      await this.store.append({ ...base, type: 'tool.action_blocked', payload: { ...payloadBase, code: error.code || 'TOOL_ARGUMENTS_DENIED' } });
      throw error;
    }

    const cost = typeof adapter.requestCost === 'function' ? Number(adapter.requestCost(args)) || 0 : 0;
    if (cost > 0 && this.budget) {
      try { this.budget.assertAffordable(context.sessionId, cost, request.tool); }
      catch (error) {
        await this.store.append({ ...base, type: 'tool.action_blocked', payload: { ...payloadBase, code: error.code || 'TOOL_BUDGET_EXCEEDED' } });
        throw error;
      }
    }

    // 意图先落盘，再谈执行。参数进事件的形态由适配器的 audit() 决定：
    // 该记路径的记路径、该记哈希的记哈希，但**不记内容**。
    await this.store.append({ ...base, type: 'tool.action_requested', payload: {
      ...payloadBase,
      arguments: adapter.audit ? adapter.audit(args) : sanitizeValue(args),
      risk: adapter.risk || 'local',
      effects: adapter.effects || [],
      request_cost: cost,
      roe: this.budget ? this.budget.snapshot(context.sessionId) : null,
    } });
    await this.store.append({ ...base, type: 'tool.action_started', payload: payloadBase });

    const started = Date.now();
    try {
      const roeAfter = cost > 0 && this.budget ? this.budget.spend(context.sessionId, cost, request.tool) : null;
      // 结果先脱敏，再交给模型 —— 顺序反过来的话，凭据已经进了模型上下文，脱敏就没有意义了。
      const result = sanitizeValue(await adapter.execute(args, adapterContext));
      await this.store.append({ ...base, type: 'tool.action_completed', payload: {
        ...payloadBase,
        elapsedMs: Date.now() - started,
        request_cost: cost,
        roe: roeAfter,
        outcome: adapter.auditResult ? adapter.auditResult(result) : sanitizeValue(result),
      } });
      return { actionId, modelToolCallId: request.modelToolCallId, result };
    } catch (error) {
      const type = error.code === 'ACTION_INTERRUPTED' ? 'tool.action_interrupted' : 'tool.action_failed';
      await this.store.append({ ...base, type, payload: { ...payloadBase, elapsedMs: Date.now() - started, code: error.code || 'TOOL_ERROR' } });
      throw error;
    }
  }
}

// ── 示例适配器 ──────────────────────────────────────────────────────────────
// 全部纯本地，只在 demoRoot 之内活动，不联网。

// 路径必须在给定根目录之内。这是适配器自己该做的事：
// 网关不知道每个工具的参数语义，参数复验只能由适配器负责。
function resolveInside(root, relative) {
  const target = resolve(root, String(relative || ''));
  const base = resolve(root);
  if (target !== base && !target.startsWith(base + sep)) throw gatewayError('DEMO_PATH_DENIED', '路径越出了示例根目录: ' + relative);
  return target;
}

export function demoAdapters({ demoRoot }) {
  const root = resolve(demoRoot);
  return [
    {
      name: 'demo_read_file',
      roles: ['pioneer', 'advisor', 'collaborate', 'observer'],
      risk: 'local',
      effects: ['read'],
      validate(args) {
        if (typeof args.path !== 'string' || !args.path.trim()) throw gatewayError('DEMO_ARGUMENT_DENIED', '需要 path');
        if (args.path.includes(String.fromCharCode(0))) throw gatewayError('DEMO_ARGUMENT_DENIED', '路径含空字节');
        return { path: args.path.trim() };
      },
      audit: args => ({ path: args.path }),
      async execute(args) {
        const text = await readFile(resolveInside(root, args.path), 'utf8');
        return { path: args.path, bytes: Buffer.byteLength(text), text };
      },
      // 结果里的正文**不进事件流**，只留字节数与哈希 —— 证据要能证明「发生过什么」，
      // 但不该顺手把读到的内容也复制成一份新的副本。
      auditResult: result => ({ bytes: result.bytes, sha256: createHash('sha256').update(result.text).digest('hex') }),
    },
    {
      name: 'demo_list_dir',
      roles: ['pioneer', 'advisor', 'collaborate', 'observer'],
      risk: 'local',
      effects: ['read'],
      validate(args) {
        if (typeof args.path !== 'string') throw gatewayError('DEMO_ARGUMENT_DENIED', '需要 path');
        return { path: args.path };
      },
      audit: args => ({ path: args.path }),
      async execute(args) {
        const names = (await readdir(resolveInside(root, args.path || '.'), { withFileTypes: true }))
          .map(entry => entry.name).sort();
        return { path: args.path, count: names.length, names: names.slice(0, 100) };
      },
      auditResult: result => ({ count: result.count }),
    },
    {
      name: 'demo_write_note',
      // observer（只读角色）拿不到它 —— 这就是「角色匹配」那一道闸。
      roles: ['pioneer', 'advisor', 'collaborate'],
      risk: 'local',
      effects: ['memory-write'],
      validate(args) {
        if (typeof args.name !== 'string' || !/^[A-Za-z0-9_-]{1,40}$/.test(args.name)) throw gatewayError('DEMO_ARGUMENT_DENIED', 'name 只允许字母数字下划线短横线');
        if (typeof args.text !== 'string' || args.text.length > 4096) throw gatewayError('DEMO_ARGUMENT_DENIED', 'text 必须是字符串且不超过 4096 字符');
        return { name: args.name, text: args.text };
      },
      audit: args => ({ name: args.name, bytes: Buffer.byteLength(args.text) }),
      async execute(args) {
        await mkdir(root, { recursive: true });
        await writeFile(join(root, args.name + '.txt'), args.text, 'utf8');
        return { name: args.name, bytes: Buffer.byteLength(args.text) };
      },
    },
    {
      name: 'demo_batch',
      // 它**不真的发请求**。存在的意义只有一个：让你看见 RoE 预算闸在**执行之前**就拒了。
      // 真实适配器在这里换成「发 N 次请求」的动作，预扣与拒绝的时机完全一样。
      roles: ['pioneer', 'collaborate'],
      risk: 'low-network',
      effects: ['network'],
      requestCost: args => args.count,
      validate(args) {
        const count = Number(args.count);
        if (!Number.isSafeInteger(count) || count < 1 || count > 1000) throw gatewayError('DEMO_ARGUMENT_DENIED', 'count 必须是 1-1000 的整数');
        return { count };
      },
      audit: args => ({ planned_requests: args.count }),
      async execute(args) {
        return { simulated: true, planned_requests: args.count, note: '本适配器不发任何请求' };
      },
    },
  ];
}

export function createDemoGateway({ store, demoRoot, roe }) {
  const gateway = new ToolGateway({ store, budget: createRequestBudget(roe || {}) });
  for (const adapter of demoAdapters({ demoRoot })) gateway.register(adapter);
  return gateway;
}
