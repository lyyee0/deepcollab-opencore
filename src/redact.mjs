/* 脱敏规则 —— 本文件由 scripts/build-opensource.mjs 从产品源码按行抽取，不要手改。
 *
 * 抽取而不是重写，是因为脱敏是「宁可多隐一点，也不能漏掉一个真口令」的规则：
 * 重写一遍等于给自己造一个更宽松的第二实现，而两份实现里更松的那份决定实际安全水平。
 *
 * 四件事，职责各不相同：
 *   redactText                值层面   —— 认出 sk- 密钥与 Bearer 令牌
 *   redactCredentialFields    结构层面 —— 键名像凭据就把值整体隐去；
 *                                     并且认得「服务器把你刚提交的请求体原样回显」这一类（FastAPI 422）
 *   StreamSanitizer           分片层面 —— 密钥跨流式分片时，不能被一段一段显示或落盘
 *   sanitizeValue / safeObject 对象层面 —— 兜底，按字段名隐去值
 */

export function cleanText(value) {
  return String(value ?? '')
    .replace(/\x1b(?:\[[0-?]*[ -\/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '')
    .replace(/\r/g, '');
}

export function redactText(value) {
  return cleanText(value)
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, '[REDACTED_API_KEY]')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+\/-]+/gi, '$1[REDACTED]');
}

// 除了 sk- 与 Bearer，还有一种更常见的泄露形态：**服务器把你刚提交的请求体原样回显**。
// FastAPI 的 422 就是典型：
//   {"detail":[{"loc":["body","employee_id"],"msg":"Field required",
//                "input":{"username":"admi","password":"123456"}}]}
// redactText 只认前缀形态的密钥，挡不住 JSON 字段。而这类响应会经过好几条通道 ——
// 测试登录的提示、认证会话工具回给模型的片段、以及模型状态快照（会落盘）——
// 所以脱敏必须放在这里、由所有通道共用，而不是各写一份。
//
// 注意：只要值之前出现过 "password" 这类字段名，值就必须隐去；
// 宁可多隐一点，也不能漏掉一个真口令。
// 字段名判定必须允许 - . 与空格。原来的字符集只有 [A-Za-z0-9_]，于是
// x-api-key / api-key / access-token / db.password / "api key" 这些**最常见的写法
// 一个都匹配不到 —— 23 个对抗输入里 13 个直接泄漏。
// 分隔符要认全三种写法：apikey / api_key / api-key / api key。
const CRED_WORDS = 'password|passwd|pwd|secret|token|credential|authorization|cookie|api[ _-]?key|access[ _-]?key|private[ _-]?key|signing[ _-]?key|session';
const CRED_FIELD_NAME = new RegExp('(?:' + CRED_WORDS + ')', 'i');
// 只认「像键名」的形状，避免把一整句说明文字当成键名去做替换。
const CRED_KEY_SHAPE = /^[A-Za-z0-9_. -]{1,64}$/;
const CRED_KEY_SOURCE = '[A-Za-z0-9_. -]{0,48}(?:' + CRED_WORDS + ')[A-Za-z0-9_. -]{0,48}';
const REDACT_MARK = '[已隐去]';

export function isCredentialFieldName(name) {
  const text = String(name ?? '');
  return CRED_KEY_SHAPE.test(text) && CRED_FIELD_NAME.test(text);
}

// 键名像凭据 → 值整体隐去，**不看值的类型**：
// {"password":{"value":"…"}} 这种包装在真实接口里很常见，只替换字符串值会原样漏出去。
function redactJsonNode(node, depth = 0) {
  if (depth > 32 || node === null || typeof node !== 'object') return node;
  if (Array.isArray(node)) return node.map(item => redactJsonNode(item, depth + 1));
  // FastAPI 的 422 把「你刚提交的值」放在 input 里，而键名是 input、不是 password；
  // 线索在兄弟字段 loc（["body","password"]）。不看 loc 就漏掉这一整类回显。
  const locSaysCredential = Array.isArray(node.loc)
    && node.loc.some(part => typeof part === 'string' && isCredentialFieldName(part));
  const out = {};
  for (const [key, value] of Object.entries(node)) {
    if (value !== null && value !== undefined && isCredentialFieldName(key)) { out[key] = REDACT_MARK; continue; }
    if (key === 'input' && locSaysCredential && typeof value === 'string') { out[key] = REDACT_MARK; continue; }
    out[key] = redactJsonNode(value, depth + 1);
  }
  return out;
}

export function redactCredentialFields(value) {
  const text = redactText(value);
  const trimmed = text.trim();
  // 能当 JSON 解析就按键路径走。正则做不对这几种形态：转义引号会截断匹配
  // （{"password":"a\"b"} 只隐去前半、尾巴照漏）、值为对象会漏、嵌套深了也漏。
  // 序列化回来时用函数式替换，免得内容里的 $& 之类被当成替换模式。
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      const before = JSON.stringify(parsed);
      const after = JSON.stringify(redactJsonNode(parsed));
      if (after !== before) return text.replace(trimmed, () => after);
    } catch { /* 不是合法 JSON：落到下面的文本规则 */ }
  }
  return text
    // "key": "value"
    .replace(new RegExp('("' + CRED_KEY_SOURCE + '"[ \t\r\n]*:[ \t\r\n]*)"[^"]*"', 'gi'), '$1"' + REDACT_MARK + '"')
    // key=value —— 查询串与表单。GET 登录恰好把口令放在 URL 查询串里。
    .replace(new RegExp('((?:^|[^A-Za-z0-9_. -])' + CRED_KEY_SOURCE + '=)[^&; \t\r\n"<>]*', 'gi'), '$1' + REDACT_MARK);
}

// 「脱敏 + 折叠空白 + 截断」的摘要形态。审批摘要、连接器发现、风险登记三处原本**逐字相同**，
// 只在默认长度上不同。policy 必须只有一份：脱敏规则改了却漏掉某一份，就是静默泄露。
export function summarize(value, length = 400) {
  return redactText(String(value ?? '')).replace(/\s+/g, ' ').trim().slice(0, length);
}

// Delay only incomplete control sequences and credential-shaped prefixes. A key
// split across SSE deltas must never be shown or persisted one fragment at a time.
export class StreamSanitizer {
  constructor() { this.pending = ''; this.escape = ''; this.surrogate = ''; this.mask = ''; }
  push(value, final = false) {
    let input = this.surrogate + String(value ?? '');
    this.surrogate = '';
    if (!final && /[\uD800-\uDBFF]$/.test(input)) {
      this.surrogate = input.slice(-1);
      input = input.slice(0, -1);
    }
    let plain = '';
    for (const char of input) {
      if (this.escape === 'esc') { this.escape = char === '[' ? 'csi' : char === ']' ? 'osc' : ''; continue; }
      if (this.escape === 'csi') { if (/[@-~]/.test(char)) this.escape = ''; continue; }
      if (this.escape === 'osc') { if (char === '\x07') this.escape = ''; else if (char === '\x1b') this.escape = 'oscEsc'; continue; }
      if (this.escape === 'oscEsc') { this.escape = char === '\\' ? '' : 'osc'; continue; }
      if (char === '\x1b') { this.escape = 'esc'; continue; }
      if (char === '\r' || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(char)) continue;
      plain += char === '\t' ? '    ' : char;
    }
    this.pending += plain;
    let result = '';
    while (this.pending) {
      if (this.mask) {
        const pattern = this.mask === 'key' ? /^[A-Za-z0-9_-]+/ : /^[A-Za-z0-9._~+\/-]+/;
        const match = this.pending.match(pattern);
        if (match) this.pending = this.pending.slice(match[0].length);
        if (!this.pending) break;
        this.mask = '';
      }
      const lower = this.pending.slice(0, 7).toLowerCase();
      if (!final && (['s', 'sk', 'sk-'].includes(this.pending) || (this.pending.length <= 7 && 'bearer '.startsWith(lower)))) break;
      if (this.pending.startsWith('sk-')) {
        const token = this.pending.slice(3).match(/^[A-Za-z0-9_-]*/)[0];
        if (token.length >= 12) {
          result += '[REDACTED_API_KEY]';
          this.pending = this.pending.slice(3 + token.length);
          this.mask = 'key';
          continue;
        }
        if (!final && this.pending.length === 3 + token.length) break;
      }
      const bearer = this.pending.match(/^Bearer\s+/i);
      if (bearer) {
        const token = this.pending.slice(bearer[0].length).match(/^[A-Za-z0-9._~+\/-]*/)[0];
        if (token) {
          result += `${bearer[0]}[REDACTED]`;
          this.pending = this.pending.slice(bearer[0].length + token.length);
          this.mask = 'bearer';
          continue;
        }
        if (!final && this.pending.length === bearer[0].length) break;
      }
      const character = String.fromCodePoint(this.pending.codePointAt(0));
      result += character;
      this.pending = this.pending.slice(character.length);
    }
    if (final) { this.escape = ''; this.surrogate = ''; this.mask = ''; }
    return result;
  }
}

function safeObject(value) {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(safeObject);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, safeObject(item)]));
}

export function sanitizeValue(value) {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(sanitizeValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key,
    /^(authorization|api[_-]?key|password|secret|access_token|refresh_token)$/i.test(key) ? '[REDACTED]' : sanitizeValue(item)]));
}
