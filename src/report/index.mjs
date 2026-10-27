// report 模块出口：序列化、脱敏与差异比对。
export { serializeReport, renderTextReport, TRUNCATION_MARK } from './serialize.mjs';
export { redactReport, isRedacted } from './redact.mjs';
export { diffAudits, sameDigest } from './diff.mjs';
