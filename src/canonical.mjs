// 稳定序列化：对象键排序，递归处理数组与嵌套对象。
// 哈希链、审批指纹、案件链都建立在它之上——同一个逻辑对象在任何进程、任何时刻都必须得到同一串字节。
export function canonicalJson(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort()
      .filter(key => value[key] !== undefined)
      .map(key => JSON.stringify(key) + ':' + canonicalJson(value[key]))
      .join(',') + '}';
  }
  return JSON.stringify(value === undefined ? null : value);
}
