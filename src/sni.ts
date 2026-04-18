/**
 * Parses raw TLS ClientHello bytes to extract the SNI hostname.
 * Implements the TLS record layer + extension parsing manually.
 */

const TLS_HANDSHAKE = 0x16;
const CLIENT_HELLO = 0x01;
const EXTENSION_SNI = 0x00;

export interface SniffResult {
  sni: string | null;
  /** Bytes remaining after the SNI extension (for re-injection) */
  remainder?: Buffer;
}

/**
 * Extract SNI from raw TLS ClientHello bytes.
 * Returns the hostname or null if not found / not a valid ClientHello.
 */
export function extractSNI(data: Buffer): string | null {
  // TLS record: content_type(1) + version(2) + length(2) + handshake...
  if (data.length < 5 || data[0] !== TLS_HANDSHAKE) return null;

  const handshakeType = data[5];
  if (handshakeType !== CLIENT_HELLO) return null;

  // Skip handshake header: length(3) + msg_length(3) + version(2) + random(32)
  let pos = 5 + 3 + 3 + 2 + 32;
  if (pos > data.length - 4) return null;

  // Session ID (1 byte length + data)
  const sessionIdLen = data[pos];
  pos += 1 + sessionIdLen;
  if (pos > data.length - 4) return null;

  // Cipher suites (2 bytes length + data)
  const cipherLen = readUInt16BE(data, pos);
  pos += 2 + cipherLen;
  if (pos > data.length - 4) return null;

  // Compression methods (1 byte length + data)
  const compLen = data[pos];
  pos += 1 + compLen;
  if (pos > data.length - 4) return null;

  // Extensions
  if (pos + 2 > data.length) return null;
  const extTotalLen = readUInt16BE(data, pos);
  pos += 2;

  let extPos = pos;
  const extEnd = pos + extTotalLen;

  while (extPos + 4 <= extEnd && extPos < data.length) {
    const extType = readUInt16BE(data, extPos);
    const extLen = readUInt16BE(data, extPos + 2);
    const extData = data.subarray(extPos + 4, extPos + 4 + extLen);

    if (extType === EXTENSION_SNI && extLen >= 5) {
      // SNI extension: inner length(2) + list_length(2) + entry_type(1) + sni_length(2) + sni
      const sniLen = readUInt16BE(extData, 3);
      if (sniLen > 0 && extData.length >= 5 + sniLen) {
        return extData.subarray(5, 5 + sniLen).toString("utf-8");
      }
    }

    extPos += 4 + extLen;
  }

  return null;
}

function readUInt16BE(buf: Buffer, offset: number): number {
  return buf.readUInt16BE(offset);
}
