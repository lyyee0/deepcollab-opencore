/* RoE（交战规则）预算闸 —— 本文件由 scripts/build-opensource.mjs 从产品源码按行抽取，不要手改。
 *
 * 它把「提示词里写的约束」变成「工具层的硬约束」：预算按会话记账、按动作**预扣**，
 * 超了在执行前就拒绝 —— 而不是跑完才发现把目标打爆。
 *
 * deny() 也一并抽了过来：它只有三行，是「带错误码的拒绝」的唯一形态。
 * 让这份发布件去依赖产品里的模块，等于把发布件的边界交给另一个仓库维护。
 */

export function deny(code, message) {
  return Object.assign(new Error(message), { code });
}

// RoE（交战规则）预算闸：把"提示词里的约束"变成"工具层的硬约束"。
//  - maxRequestsPerSession：本会话允许发出的目标请求总数（默认 500）
//  - requestsPerMinute：每分钟速率上限（默认 60），批量工具会据此收敛自己的 -t/--delay/-rate/-rl/-Pause
// 预算是"按会话记账、按动作预扣"：启动前先估算成本，超了直接拒绝，避免跑完才发现把目标打爆。
export function createRequestBudget(roe = {}) {
  const maxRequests = Number.isSafeInteger(roe.maxRequestsPerSession) && roe.maxRequestsPerSession > 0 ? roe.maxRequestsPerSession : 500;
  const requestsPerMinute = Number.isSafeInteger(roe.requestsPerMinute) && roe.requestsPerMinute > 0 ? roe.requestsPerMinute : 60;
  const ledger = new Map();
  const entryOf = sessionId => {
    let entry = ledger.get(sessionId);
    if (!entry) {
      entry = { used: 0, byTool: {} };
      ledger.set(sessionId, entry);
    }
    return entry;
  };
  return {
    maxRequests,
    requestsPerMinute,
    // 批量工具用来把自己收敛到 RoE 之内的小工具函数
    clampRate(requested) {
      const value = Number(requested) || requestsPerMinute;
      return Math.max(1, Math.min(value, requestsPerMinute));
    },
    delayMs() {
      return Math.max(0, Math.ceil(60000 / requestsPerMinute));
    },
    snapshot(sessionId) {
      const entry = entryOf(sessionId);
      return {
        used: entry.used,
        remaining: Math.max(0, maxRequests - entry.used),
        maxRequests,
        requestsPerMinute,
        byTool: { ...entry.byTool },
      };
    },
    assertAffordable(sessionId, cost, tool) {
      const entry = entryOf(sessionId);
      const remaining = Math.max(0, maxRequests - entry.used);
      if (cost > remaining) {
        throw deny('TOOL_BUDGET_EXCEEDED',
          '该动作预计发出 ' + cost + ' 次请求，超过本会话剩余预算（剩余 ' + remaining + ' / 共 ' + maxRequests
          + '，速率上限 ' + requestsPerMinute + '/分钟）。请改用更小的字典、更窄的模板集，或用单请求方式逐点验证。');
      }
      return true;
    },
    spend(sessionId, cost, tool) {
      const entry = entryOf(sessionId);
      entry.used += cost;
      if (tool) entry.byTool[tool] = (entry.byTool[tool] || 0) + cost;
      return this.snapshot(sessionId);
    },
  };
}
