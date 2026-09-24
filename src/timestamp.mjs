import { X509Certificate, createHash, randomBytes, verify as cryptoVerify } from 'node:crypto';

// RFC 3161 可信时间戳客户端：零依赖实现 DER 编解码、CMS SignedData 解析与签名校验。
//
// 它要回答的问题是 L1 答不了的那一个：**这份检查点在某个真实时刻就已经存在**。
// 本机时钟可以随便改，哈希链和签名都挡不住"事后补写一条看起来很早的记录"；
// 第三方时间戳把"存在性"锚定到一个 DeepCollab 无法单方面伪造的时刻上。
//
// 明确边界：本模块能验证"令牌内部自洽、且确实由其内嵌证书签署、且时间戳哈希等于我们的链头"，
// 但**不宣称**完成 X.509 信任链路径校验（Node 没有内置路径校验）。要更强保证，
// 用 audit.timestamp.certFingerprint 固定 TSA 证书指纹，或用 openssl ts -verify 复核。

export const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const SHA384_OID = '2.16.840.1.101.3.4.2.2';
const SHA512_OID = '2.16.840.1.101.3.4.2.3';
const SIGNED_DATA_OID = '1.2.840.113549.1.7.2';
const TST_INFO_OID = '1.2.840.113549.1.9.16.1.4';
const ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

const DIGEST_BY_OID = {
  [SHA256_OID]: 'sha256',
  [SHA384_OID]: 'sha384',
  [SHA512_OID]: 'sha512',
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.4': 'sha224',
};

// CMS signatureAlgorithm / digestAlgorithm OID → node:crypto 的摘要名。null 表示算法自带摘要（Ed25519）。
const SIGNATURE_DIGEST_BY_OID = {
  '1.2.840.113549.1.1.5': 'sha1',
  '1.2.840.113549.1.1.11': 'sha256',
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
  '1.2.840.113549.1.1.14': 'sha224',
  '1.2.840.10045.4.3.2': 'sha256',
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
  '1.3.101.112': null,
};

export const PKI_STATUS = Object.freeze({
  0: 'granted', 1: 'grantedWithMods', 2: 'rejection', 3: 'waiting', 4: 'revocationWarning', 5: 'revocationNotification',
});

// 公共 TSA 预设。默认选 freetsa：免费、无需注册、原生 HTTPS。
export const DEFAULT_TSA_URL = 'https://freetsa.org/tsr';
export const TSA_PRESETS = Object.freeze({
  freetsa: 'https://freetsa.org/tsr',
  sectigo: 'https://timestamp.sectigo.com',
  digicert: 'https://timestamp.digicert.com',
  moda: 'https://rfc3161.ai.moda',
});

export function timestampError(code, message) {
  return Object.assign(new Error(message), { code, exitCode: 2 });
}

// —— DER ————————————————————————————————————————————————

function derLength(length) {
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  let value = length;
  while (value > 0) { bytes.unshift(value & 0xff); value >>>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

const derWrap = (tag, content) => Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
// 测试与上层构造器需要显式标签包装（例如 signedAttrs 的隐式 [0]）。
export const derRaw = derWrap;
export const derSequence = (...parts) => derWrap(0x30, Buffer.concat(parts));
export const derSet = (...parts) => derWrap(0x31, Buffer.concat(parts));
export const derOctetString = value => derWrap(0x04, Buffer.isBuffer(value) ? value : Buffer.from(value));
export const derNull = () => derWrap(0x05, Buffer.alloc(0));
export const derBoolean = value => derWrap(0x01, Buffer.from([value ? 0xff : 0x00]));

export function derInteger(value) {
  let buffer = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'hex');
  if (!Buffer.isBuffer(value) && typeof value === 'number') {
    const bytes = [];
    let rest = value;
    do { bytes.unshift(rest & 0xff); rest = Math.floor(rest / 256); } while (rest > 0);
    buffer = Buffer.from(bytes);
  }
  let start = 0;
  while (start < buffer.length - 1 && buffer[start] === 0) start += 1;
  buffer = buffer.subarray(start);
  if (buffer[0] & 0x80) buffer = Buffer.concat([Buffer.from([0x00]), buffer]);
  return derWrap(0x02, buffer);
}

export function encodeOid(dotted) {
  const parts = String(dotted).split('.').map(Number);
  if (parts.length < 2 || parts.some(part => !Number.isSafeInteger(part) || part < 0)) throw timestampError('TS_OID_INVALID', 'OID 格式无效: ' + dotted);
  const bytes = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const stack = [part & 0x7f];
    let rest = Math.floor(part / 128);
    while (rest > 0) { stack.unshift((rest & 0x7f) | 0x80); rest = Math.floor(rest / 128); }
    bytes.push(...stack);
  }
  return Buffer.from(bytes);
}

export const derOid = dotted => derWrap(0x06, encodeOid(dotted));

export function decodeOid(buffer) {
  const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let value = 0;
  for (let index = 1; index < bytes.length; index += 1) {
    value = value * 128 + (bytes[index] & 0x7f);
    if (!(bytes[index] & 0x80)) { parts.push(value); value = 0; }
  }
  return parts.join('.');
}

export function readTlv(buffer, offset) {
  if (offset + 2 > buffer.length) throw timestampError('TS_DER_TRUNCATED', 'DER 结构在偏移 ' + offset + ' 处被截断');
  const tag = buffer[offset];
  let cursor = offset + 1;
  let length = buffer[cursor];
  cursor += 1;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) throw timestampError('TS_DER_INVALID', '不支持的长度编码');
    length = 0;
    for (let index = 0; index < count; index += 1) length = length * 256 + buffer[cursor + index];
    cursor += count;
  }
  const end = cursor + length;
  if (end > buffer.length) throw timestampError('TS_DER_TRUNCATED', 'DER 内容超出缓冲区');
  // full = 含标签与长度的完整 TLV，导出内嵌证书等子结构时必须用它，而不是 content。
  return { tag, length, start: cursor, end, content: buffer.subarray(cursor, end), full: buffer.subarray(offset, end), next: end };
}

function requireTag(tlv, tag, label) {
  if (tlv.tag !== tag) throw timestampError('TS_DER_UNEXPECTED', label + ' 的标签应为 0x' + tag.toString(16) + '，实际 0x' + tlv.tag.toString(16));
  return tlv;
}

function children(buffer, parent) {
  const out = [];
  let cursor = parent.start;
  while (cursor < parent.end) {
    const child = readTlv(buffer, cursor);
    out.push(child);
    cursor = child.next;
  }
  return out;
}

// —— 请求 ————————————————————————————————————————————————

export function buildTimestampRequest(digest, { policyId = null, nonce = null, certReq = true } = {}) {
  const hash = Buffer.isBuffer(digest) ? digest : Buffer.from(String(digest), 'hex');
  const parts = [
    derInteger(1),
    derSequence(derSequence(derOid(SHA256_OID), derNull()), derOctetString(hash)),
  ];
  if (policyId) parts.push(derOid(policyId));
  if (nonce) parts.push(derInteger(nonce));
  // 要求 TSA 把签名证书一并放进令牌：否则离线无法验证，等于把可验证性留在了服务端。
  if (certReq) parts.push(derBoolean(true));
  return derSequence(...parts);
}

export function parseTimestampResponse(buffer) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  const outer = requireTag(readTlv(buf, 0), 0x30, 'TimeStampResp');
  const statusInfo = requireTag(readTlv(buf, outer.start), 0x30, 'PKIStatusInfo');
  const statusCode = requireTag(readTlv(buf, statusInfo.start), 0x02, 'PKIStatusInfo.status');
  const code = statusCode.content.length ? statusCode.content.readUIntBE(0, statusCode.content.length) : 0;
  const statusText = [];
  for (const child of children(buf, statusInfo).slice(1)) {
    if (child.tag === 0x30) statusText.push(child.content.toString('utf8'));
    if (child.tag === 0x03) statusText.push('failInfo=0x' + child.content.toString('hex'));
  }
  if (code !== 0 && code !== 1) {
    throw timestampError('TS_REFUSED', 'TSA 拒绝签发时间戳：' + (PKI_STATUS[code] || code) + (statusText.length ? '（' + statusText.join(' ') + '）' : ''));
  }
  // 令牌紧跟在 PKIStatusInfo 之后；判断有没有令牌要比对 statusInfo 的结束位置，
  // 而不是外层 SEQUENCE 的结束位置（两者本来就相等）。
  if (statusInfo.next >= outer.end) throw timestampError('TS_TOKEN_MISSING', 'TSA 返回 granted 但没有附带时间戳令牌');
  return { status: code, statusText, token: buf.subarray(statusInfo.next, outer.end) };
}

// —— 令牌解析与校验 ————————————————————————————————————————

function parseGeneralizedTime(text) {
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(text.trim());
  if (!match) return { iso: null, raw: text };
  const [, year, month, day, hour, minute, second, fraction] = match;
  const millis = fraction ? Number(('0.' + fraction)) * 1000 : 0;
  const date = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second), Math.round(millis)));
  return { iso: date.toISOString(), raw: text };
}

const normalizeFingerprint = value => String(value || '').replace(/[^0-9A-Fa-f]/g, '').toUpperCase();

function pemOf(buffer) {
  const base64 = buffer.toString('base64').replace(/(.{64})/g, '$1\n');
  return '-----BEGIN CERTIFICATE-----\n' + base64.trimEnd() + '\n-----END CERTIFICATE-----\n';
}

// 解析 CMS SignedData，取出 TSTInfo、签名者证书，并就地完成三重校验：
//   1) signedAttrs 里的 messageDigest 等于 eContent 的摘要
//   2) 签名能用内嵌证书的公钥验通
//   3) TSTInfo 的 messageImprint 等于我们给出的链头摘要
export function parseTimestampToken(token, { expectedImprint = null, pinnedFingerprint = null } = {}) {
  const buf = Buffer.isBuffer(token) ? token : Buffer.from(token);
  const outer = requireTag(readTlv(buf, 0), 0x30, 'ContentInfo');
  const contentType = requireTag(readTlv(buf, outer.start), 0x06, 'ContentInfo.contentType');
  if (decodeOid(contentType.content) !== SIGNED_DATA_OID) throw timestampError('TS_TOKEN_NOT_SIGNED_DATA', '时间戳令牌不是 CMS SignedData');
  const explicit = requireTag(readTlv(buf, contentType.next), 0xa0, 'ContentInfo.content');
  const signedData = requireTag(readTlv(buf, explicit.start), 0x30, 'SignedData');
  const parts = children(buf, signedData);
  const encap = parts[2];
  if (!encap || encap.tag !== 0x30) throw timestampError('TS_TOKEN_INVALID', 'SignedData 缺少 encapContentInfo');
  const encapChildren = children(buf, encap);
  const eContent = encapChildren.find(child => child.tag === 0xa0);
  if (!eContent) throw timestampError('TS_TOKEN_INVALID', 'SignedData 没有分离内容（eContent）');
  const octet = requireTag(readTlv(buf, eContent.start), 0x04, 'eContent');
  const tstInfoDer = buf.subarray(octet.start, octet.end);
  const eContentType = encapChildren.find(child => child.tag === 0x06);
  if (eContentType && decodeOid(eContentType.content) !== TST_INFO_OID) {
    throw timestampError('TS_TOKEN_NOT_TSTINFO', 'eContentType 不是 id-ct-TSTInfo');
  }

  // 注意：digestAlgorithms 也是 SET（0x31），不能按标签找 signerInfos —— 它是 SignedData 的最后一个孩子。
  const certificatesTlv = parts.find(child => child.tag === 0xa0);
  const signerInfos = parts[parts.length - 1];
  if (!signerInfos || signerInfos.tag !== 0x31) throw timestampError('TS_TOKEN_INVALID', 'SignedData 缺少 signerInfos');
  const certs = certificatesTlv
    ? children(buf, certificatesTlv).filter(child => child.tag === 0x30).map(child => child.full)
    : [];
  if (!certs.length) throw timestampError('TS_NO_CERTIFICATE', '令牌未内嵌签名证书；请在请求中设置 certReq');

  const signerInfo = children(buf, signerInfos).find(child => child.tag === 0x30);
  if (!signerInfo) throw timestampError('TS_TOKEN_INVALID', 'signerInfos 为空');
  const signerParts = children(buf, signerInfo);
  let index = 3;
  let signedAttrs = null;
  if (signerParts[index] && signerParts[index].tag === 0xa0) { signedAttrs = signerParts[index]; index += 1; }
  const signatureAlgorithm = signerParts[index];
  const signature = signerParts[index + 1];
  if (!signatureAlgorithm || !signature) throw timestampError('TS_TOKEN_INVALID', 'SignerInfo 结构不完整');

  const signatureOid = decodeOid(children(buf, signatureAlgorithm)[0].content);
  const digestAlgorithmOid = decodeOid(children(buf, children(buf, signerInfo)[2])[0].content);
  // 优先用 SignerInfo 自己的 digestAlgorithm；rsaEncryption 这类 OID 本身不含摘要信息。
  const digestName = DIGEST_BY_OID[digestAlgorithmOid]
    || (signatureOid in SIGNATURE_DIGEST_BY_OID ? SIGNATURE_DIGEST_BY_OID[signatureOid] : null)
    || 'sha256';

  // signedAttrs 在签名时是 SET OF（0x31），线路上是隐式 [0]（0xa0）；校验必须换回 0x31 重新编码。
  const signedAttrsDer = signedAttrs ? derWrap(0x31, buf.subarray(signedAttrs.start, signedAttrs.end)) : null;
  let messageDigest = null;
  if (signedAttrs) {
    for (const attribute of children(buf, signedAttrs)) {
      const attributeParts = children(buf, attribute);
      if (!attributeParts.length || attributeParts[0].tag !== 0x06) continue;
      if (decodeOid(attributeParts[0].content) !== ATTR_MESSAGE_DIGEST) continue;
      const set = attributeParts[1];
      const value = children(buf, set)[0];
      if (value) messageDigest = value.content;
    }
  }

  const contentDigestName = DIGEST_BY_OID[digestAlgorithmOid] || 'sha256';
  const actualContentDigest = createHash(contentDigestName).update(tstInfoDer).digest();
  const digestMatches = messageDigest ? messageDigest.equals(actualContentDigest) : false;

  const x509 = certs.map(der => {
    let certificate;
    try { certificate = new X509Certificate(der); } catch { certificate = null; }
    return certificate ? { der, certificate, fingerprint: normalizeFingerprint(certificate.fingerprint256) } : null;
  }).filter(Boolean);

  let signer = null;
  let signatureValid = false;
  for (const candidate of x509) {
    if (!signedAttrsDer) break;
    try {
      if (cryptoVerify(digestName, signedAttrsDer, candidate.certificate.publicKey, signature.content)) {
        signer = candidate;
        signatureValid = true;
        break;
      }
    } catch { /* 换下一张证书 */ }
  }
  if (!signer && x509.length === 1) signer = x509[0];

  // TSTInfo
  const tstInfo = requireTag(readTlv(tstInfoDer, 0), 0x30, 'TSTInfo');
  const tstParts = children(tstInfoDer, tstInfo);
  const policy = tstParts[1] ? decodeOid(tstParts[1].content) : null;
  const imprintSeq = tstParts[2];
  const imprintParts = children(tstInfoDer, imprintSeq);
  const imprintAlgorithm = decodeOid(children(tstInfoDer, imprintParts[0])[0].content);
  const imprint = imprintParts[1].content;
  const serialNumber = tstParts[3] ? tstParts[3].content.toString('hex') : null;
  const genTime = tstParts[4] ? parseGeneralizedTime(tstParts[4].content.toString('ascii')) : { iso: null, raw: null };
  const nonceTlv = tstParts.slice(5).find(child => child.tag === 0x02);

  const imprintMatches = expectedImprint
    ? imprint.equals(Buffer.from(String(expectedImprint).replace(/^0x/, ''), 'hex'))
    : null;
  const pinMatches = pinnedFingerprint ? signer?.fingerprint === normalizeFingerprint(pinnedFingerprint) : null;

  const selfSigned = x509.find(entry => entry.certificate.subject === entry.certificate.issuer) || null;
  const ok = signatureValid && digestMatches && imprintMatches !== false && pinMatches !== false;

  return {
    ok,
    status: 'granted',
    policy, serialNumber,
    genTime: genTime.iso, genTimeRaw: genTime.raw,
    imprintAlgorithm, imprint: imprint.toString('hex'),
    nonce: nonceTlv ? nonceTlv.content.toString('hex') : null,
    signatureAlgorithm: signatureOid,
    verified: { signature: signatureValid, messageDigest: digestMatches, imprint: imprintMatches, pinned: pinMatches },
    signer: signer ? {
      subject: signer.certificate.subject, issuer: signer.certificate.issuer,
      serialNumber: signer.certificate.serialNumber, fingerprint256: signer.fingerprint,
      validFrom: signer.certificate.validFrom, validTo: signer.certificate.validTo,
      selfSigned: signer.certificate.subject === signer.certificate.issuer,
    } : null,
    chain: x509.map(entry => ({ subject: entry.certificate.subject, fingerprint256: entry.fingerprint })),
    rootFingerprint: selfSigned ? selfSigned.fingerprint : null,
    signerCertificatePem: signer ? pemOf(signer.der) : null,
    tstInfoDer,
  };
}

export function verifyTimestampToken(token, { expectedImprint = null, pinnedFingerprint = null } = {}) {
  try { return { ...parseTimestampToken(token, { expectedImprint, pinnedFingerprint }), error: null }; }
  catch (error) { return { ok: false, error: error.code || 'TS_VERIFY_FAILED', message: error.message, verified: {}, signer: null }; }
}

export function defaultNonce() {
  const bytes = randomBytes(8);
  bytes[0] &= 0x7f;
  return bytes;
}

export async function requestTimestamp(network, digestHex, {
  url = DEFAULT_TSA_URL, timeoutMs = 15000, policyId = null, nonce = null, signal = null, correlation = {},
} = {}) {
  const request = buildTimestampRequest(Buffer.from(String(digestHex), 'hex'), { policyId, nonce: nonce || defaultNonce(), certReq: true });
  const chunks = [];
  const response = await network.request(url, {
    kind: 'timestamp',
    method: 'POST',
    headers: { 'content-type': 'application/timestamp-query', accept: 'application/timestamp-reply' },
    // 原始 DER 必须是二进制安全的；text 通道会在 UTF-8 解码时改写字节。
    body: request,
    timeoutMs,
    maxBytes: 4 * 1024 * 1024,
    correlation,
    signal,
    onChunk: async chunk => { chunks.push(Buffer.from(chunk)); },
  });
  if (response.status !== 200) throw timestampError('TS_HTTP_' + response.status, 'TSA 返回 HTTP ' + response.status);
  const raw = Buffer.concat(chunks);
  if (!raw.length) throw timestampError('TS_EMPTY_RESPONSE', 'TSA 返回空响应');
  const parsed = parseTimestampResponse(raw);
  return { ...parsed, raw, request, url };
}
