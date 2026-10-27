// CRC32（IEEE 802.3，反射多项式 0xEDB88320）实现。
// 结果与 node:zlib 的 crc32 一致，这里自带实现以避免依赖特定 Node 小版本的 zlib.crc32，
// 并在测试里与 zlib.crc32 交叉验证。只读、零写入、零外部依赖。

/** 预计算的 CRC32 查找表，进程内惰性构造一次。 */
const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n >>> 0;
    for (let k = 0; k < 8; k += 1) {
      c = (c & 1) === 1 ? (0xedb88320 ^ (c >>> 1)) >>> 0 : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

/**
 * 计算一段字节的 CRC32。
 * @param {Buffer | Uint8Array} data 输入字节
 * @returns {number} 无符号 32 位整数
 */
export function crc32(data) {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i += 1) {
    crc = (CRC32_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >>> 8)) >>> 0;
  }
  return (crc ^ 0xffffffff) >>> 0;
}
