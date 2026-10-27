// container 模块出口：只读容器识别与镜像解析。
export {
  detectContainer,
  isSupportedContainer,
  SUPPORTED_CONTAINERS,
  DETECTION_PREFIX_BYTES,
  SAFETENSORS_HEADER_PROBE_MAX,
  safetensorsHeaderLength,
  peSignatureEnd,
  detectionProbeLength,
} from './detect.mjs';
export { identifyArtifact } from './identify.mjs';
