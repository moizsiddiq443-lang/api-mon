// crypt.mjs — envelope helpers. Format: v1:<12-byte-iv hex>:<gzip + ciphertext + tag, base64>
import { gzipSync, gunzipSync } from 'node:zlib';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

export function keyFromEnv() {
  const hex = process.env.KEY || '';
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('key missing or malformed');
  return Buffer.from(hex, 'hex');
}

export function seal(text, key) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([c.update(gzipSync(Buffer.from(text, 'utf8'))), c.final()]);
  return `v1:${iv.toString('hex')}:${Buffer.concat([body, c.getAuthTag()]).toString('base64')}`;
}

export function open(blob, key) {
  const [tag1, ivHex, b64] = String(blob).split(':');
  if (tag1 !== 'v1') throw new Error('bad blob version');
  const buf = Buffer.from(b64, 'base64');
  const ct = buf.subarray(0, buf.length - 16);
  const tag = buf.subarray(buf.length - 16);
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  d.setAuthTag(tag);
  return gunzipSync(Buffer.concat([d.update(ct), d.final()])).toString('utf8');
}

export function sealJson(obj, key) { return seal(JSON.stringify(obj), key); }
export function openJson(blob, key) { return JSON.parse(open(blob, key)); }

export function loadConfig(path, key) {
  return JSON.parse(open(readFileSync(path, 'utf8'), key));
}