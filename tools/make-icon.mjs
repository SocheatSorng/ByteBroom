// Draws ByteBroom's app icon (a broom on a rounded square) and writes src-tauri/icons/icon.ico
// (16, 24, 32, 48, 64 and 256 px PNG frames) and icon.png (512 px). No packages: Node's zlib only.
// Usage, in your project folder:  node tools/make-icon.mjs
import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const out = join(dirname(fileURLToPath(import.meta.url)), "..", "src-tauri", "icons");

// Signed distance helpers, in a 0..1 square.
const roundedSquare = (x, y, r) => {
  const qx = Math.abs(x - 0.5) - (0.5 - r - 0.03);
  const qy = Math.abs(y - 0.5) - (0.5 - r - 0.03);
  return Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - r;
};
const segment = (x, y, ax, ay, bx, by) => {
  const px = x - ax, py = y - ay, dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, (px * dx + py * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - dx * t, py - dy * t);
};

function pixel(x, y) {
  const bg = roundedSquare(x, y, 0.18);
  if (bg > 0) return [0, 0, 0, 0];
  let c = [22, 94, 120]; // deep teal
  // Handle: a light diagonal bar from top right to the middle.
  if (segment(x, y, 0.74, 0.2, 0.48, 0.56) < 0.045) c = [236, 226, 204];
  // Bristles: a fan below the handle's end.
  const bx = x - 0.45, by = y - 0.6;
  const inFan = by > -0.05 && by < 0.2 && Math.abs(bx + by * 0.55) < 0.1 + by * 0.6;
  if (inFan) c = (Math.floor((bx + by * 0.55) * 60) % 2 === 0) ? [245, 190, 70] : [228, 160, 40];
  // Soft edge on the background shape.
  const a = Math.round(255 * Math.min(1, -bg * 200));
  return [...c, a];
}

function png(size) {
  const raw = Buffer.alloc(size * (size * 4 + 1));
  const ss = 4; // supersampling per axis
  for (let j = 0; j < size; j++) {
    raw[j * (size * 4 + 1)] = 0; // filter: none
    for (let i = 0; i < size; i++) {
      const acc = [0, 0, 0, 0];
      for (let sj = 0; sj < ss; sj++) {
        for (let si = 0; si < ss; si++) {
          const p = pixel((i + (si + 0.5) / ss) / size, (j + (sj + 0.5) / ss) / size);
          for (let k = 0; k < 3; k++) acc[k] += p[k] * p[3];
          acc[3] += p[3];
        }
      }
      const o = j * (size * 4 + 1) + 1 + i * 4;
      for (let k = 0; k < 3; k++) raw[o + k] = acc[3] ? Math.round(acc[k] / acc[3]) : 0;
      raw[o + 3] = Math.round(acc[3] / (ss * ss));
    }
  }
  const crcTable = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc = (buf) => {
    let c = 0xffffffff;
    for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
    const sum = Buffer.alloc(4);
    sum.writeUInt32BE(crc(body));
    return Buffer.concat([len, body, sum]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function ico(sizes) {
  const frames = sizes.map(png);
  const header = Buffer.alloc(6 + 16 * sizes.length);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2); // icon
  header.writeUInt16LE(sizes.length, 4);
  let offset = header.length;
  sizes.forEach((s, n) => {
    const e = 6 + 16 * n;
    header[e] = s >= 256 ? 0 : s;
    header[e + 1] = s >= 256 ? 0 : s;
    header.writeUInt16LE(1, e + 4); // planes
    header.writeUInt16LE(32, e + 6); // bits per pixel
    header.writeUInt32LE(frames[n].length, e + 8);
    header.writeUInt32LE(offset, e + 12);
    offset += frames[n].length;
  });
  return Buffer.concat([header, ...frames]);
}

mkdirSync(out, { recursive: true });
writeFileSync(join(out, "icon.ico"), ico([16, 24, 32, 48, 64, 256]));
writeFileSync(join(out, "icon.png"), png(512));
console.log(`wrote ${out}`);
