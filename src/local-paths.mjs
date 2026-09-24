// File paths are a separate network route on Windows (UNC / SMB).
// Accept local filesystem paths only, not remote or device namespaces.
export function assertLocalPath(value) {
  if (typeof value !== 'string' || !value || value.includes('\0')) throw new Error('文件路径必须是非空字符串');
  const normalized = value.replace(/\\/g, '/');
  if (normalized.startsWith('//') || /^[a-z][a-z0-9+.-]*:\/\//i.test(normalized)) {
    const error = new Error('工作区、日志与导入路径必须是本地路径；拒绝 UNC、网络共享和 URL 路径');
    error.code = 'REMOTE_PATH_DENIED';
    error.exitCode = 3;
    throw error;
  }
  return value;
}
