import { realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path';

// Resolve the nearest existing ancestor so symlinks and Windows junctions in
// existing path components are checked even when the final file is new.
function physicalPath(value) {
  let candidate = resolve(value);
  const suffix = [];
  while (true) {
    try { return resolve(realpathSync.native(candidate), ...suffix.reverse()); }
    catch (error) {
      if (!['ENOENT', 'ENOTDIR'].includes(error.code)) throw error;
      const parent = dirname(candidate);
      if (parent === candidate) throw error;
      suffix.push(basename(candidate));
      candidate = parent;
    }
  }
}

function isWithin(root, candidate) {
  const rel = relative(root, candidate);
  return rel === '' || (rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel));
}

export function assertPathWithin(allowedRoot, value) {
  if (typeof allowedRoot !== 'string' || !allowedRoot) throw new Error('允许根目录必须是非空本地路径');
  const root = physicalPath(allowedRoot);
  const target = physicalPath(value);
  if (!isWithin(root, target)) {
    const error = new Error('路径越出允许目录（包括符号链接或 junction 解析后的真实路径）');
    error.code = 'REMOTE_PATH_DENIED';
    error.exitCode = 3;
    throw error;
  }
  return target;
}

// File paths are a separate network route on Windows (UNC / SMB).
// Callers with a workspace or package root also enforce physical containment.
export function assertLocalPath(value, allowedRoot = null) {
  if (typeof value !== 'string' || !value || value.includes('\0')) throw new Error('文件路径必须是非空字符串');
  const normalized = value.replace(/\\/g, '/');
  if (normalized.startsWith('//') || /^[a-z][a-z0-9+.-]*:\/\//i.test(normalized)) {
    const error = new Error('工作区、日志与导入路径必须是本地路径；拒绝 UNC、网络共享和 URL 路径');
    error.code = 'REMOTE_PATH_DENIED';
    error.exitCode = 3;
    throw error;
  }
  return allowedRoot ? assertPathWithin(allowedRoot, value) : value;
}
