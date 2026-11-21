/* DBC / ASC / BLF / TRC 浏览器端解析器（无后端依赖） */
(function (global) {
"use strict";

const MAX_FRAMES = 200000;
const DLC_LEN = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64];

function unescapeDbc(s) {
  return String(s == null ? "" : s).replace(/\\r/g, "\r").replace(/\\n/g, "\n")
    .replace(/\\t/g, "\t").replace(/\\"/g, '"').replace(/\\\\/g, "\\");
}
function num(v, dflt) {
  if (v === "" || v == null) return dflt;
  const n = Number(v);
  return Number.isFinite(n) ? n : dflt;
}
function dbcNum(v) {
  if (v == null || v === "") return "0";
  const n = Number(v);
  if (!Number.isFinite(n)) return "0";
  return Number.isInteger(n) ? String(n) : String(Number(n.toPrecision(10)));
}
function dbcIdent(name, fallback) {
  let s = String(name || "").replace(/[^A-Za-z0-9_]/g, "_").replace(/^_+|_+$/g, "");
  if (!s) s = fallback;
  if (/^\d/.test(s)) s = "_" + s;
  return s;
}
function dbcQuote(v) {
  return String(v == null ? "" : v).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/[\r\n]+/g, " ");
}
function hexId(id) { return "0x" + (Number(id) >>> 0).toString(16).toUpperCase(); }
function cleanData(s) { return String(s || "").replace(/[ ,]/g, "").toUpperCase(); }

function decodeDbcText(buf) {
  const bytes = new Uint8Array(buf);
  const candidates = [
    ["utf-8", "utf-8"],
    ["gb18030", "gb18030"],
    ["windows-1252", "cp1252"],
    ["iso-8859-1", "latin-1"],
  ];
  let best = null;
  for (const [enc, label] of candidates) {
    try {
      const text = new TextDecoder(enc, { fatal: true }).decode(bytes).replace(/^\uFEFF/, "");
      let cjk = 0, bad = 0;
      for (const ch of text) {
        const o = ch.codePointAt(0);
        if ((o >= 0x4e00 && o <= 0x9fff) || (o >= 0x3400 && o <= 0x4dbf)) cjk++;
        else if (ch === "\ufffd" || (o < 32 && ch !== "\t" && ch !== "\n" && ch !== "\r")) bad++;
        else if ("ÃÂÐÑØÙðÿ".includes(ch)) bad++;
      }
      const score = cjk * 3 - bad * 5;
      if (!best || score > best.score) best = { text, score, label };
    } catch (e) { /* 继续尝试下一种编码 */ }
  }
  if (!best) throw new Error("DBC 编码识别失败");
  return best.text;
}

function parseChoices(text) {
  const out = {};
  String(text || "").replace(/；/g, ";").split(";").forEach(part => {
    const m = part.match(/^\s*(-?\d+)\s*=\s*(.+?)\s*$/);
    if (m) out[m[1]] = m[2];
  });
  return out;
}

function parseDbc(text) {
  const lines = String(text || "").replace(/\r/g, "").split("\n");
  const messages = [];
  const byRawId = new Map();
  const cmSig = new Map();
  const cmMsg = new Map();
  const vals = new Map();

  for (const line of lines) {
    let m = line.match(/^\s*CM_\s+SG_\s+(\d+)\s+(\S+)\s+"((?:\\.|[^"])*)"\s*;/);
    if (m) { cmSig.set(m[1] + "|" + m[2], unescapeDbc(m[3])); continue; }
    m = line.match(/^\s*CM_\s+BO_\s+(\d+)\s+"((?:\\.|[^"])*)"\s*;/);
    if (m) { cmMsg.set(m[1], unescapeDbc(m[2])); continue; }
    m = line.match(/^\s*VAL_\s+(\d+)\s+(\S+)\s+(.+?)\s*;/);
    if (m) {
      const choices = {};
      const re = /(-?\d+)\s+"((?:\\.|[^"])*)"/g;
      let x;
      while ((x = re.exec(m[3])) !== null) choices[x[1]] = unescapeDbc(x[2]);
      vals.set(m[1] + "|" + m[2], choices);
    }
  }

  let cur = null;
  const sgRe = /^\s*SG_\s+(\S+)(?:\s+(M|m\d+(?:,\d+)*))?\s*:\s*(\d+)\|(\d+)@([01])([+-])\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)\s*\[\s*([^|]+?)\s*\|\s*([^\]]+?)\s*\]\s*"((?:\\.|[^"])*)"/;
  for (const line of lines) {
    let m = line.match(/^\s*BO_\s+(\d+)\s+(\S+)\s*:\s*(\d+)\s+(\S+)/);
    if (m) {
      const rawId = Number(m[1]);
      const ext = !!(rawId & 0x80000000) || (rawId & 0x1fffffff) > 0x7ff;
      const id = rawId & 0x1fffffff;
      cur = {
        id, id_hex: hexId(id), raw_id: rawId, name: m[2], dlc: Number(m[3]) || 0,
        extended: ext, cycle_time: null, comment: cmMsg.get(String(rawId)) || "",
        signals: [],
      };
      messages.push(cur);
      byRawId.set(String(rawId), cur);
      byRawId.set(String(id), cur);
      continue;
    }
    if (!cur) continue;
    m = line.match(sgRe);
    if (!m) continue;
    const muxToken = m[2] || "";
    const isMux = muxToken === "M";
    const mux = /^m\d+/.test(muxToken) ? muxToken.replace(/^m/, "").split(",").map(Number) : null;
    const sig = {
      name: m[1], start: Number(m[3]), length: Number(m[4]),
      byte_order: m[5] === "1" ? "little_endian" : "big_endian",
      is_signed: m[6] === "-", scale: num(m[7], 1), offset: num(m[8], 0),
      unit: unescapeDbc(m[11]), min: num(m[9], null), max: num(m[10], null),
      choices: vals.get(String(cur.raw_id) + "|" + m[1]) || {},
      mux, is_mux: isMux,
      comment: cmSig.get(String(cur.raw_id) + "|" + m[1]) || "",
      custom: false,
    };
    cur.signals.push(sig);
  }
  messages.sort((a, b) => a.id - b.id);
  return messages;
}

function extractRaw(data, start, length, byteOrder, isSigned) {
  if (!(length >= 1 && length <= 64)) throw new Error("信号长度超出范围");
  let val = 0n;
  if (byteOrder === "little_endian") {
    for (let i = 0; i < length; i++) {
      const bit = start + i;
      if (Math.floor(bit / 8) >= data.length) throw new Error("信号超出帧数据长度");
      if (data[bit >> 3] & (1 << (bit & 7))) val |= 1n << BigInt(i);
    }
  } else {
    let bit = start;
    for (let i = 0; i < length; i++) {
      if (Math.floor(bit / 8) >= data.length) throw new Error("信号超出帧数据长度");
      if (data[bit >> 3] & (1 << (bit & 7))) val |= 1n << BigInt(length - 1 - i);
      bit = (bit % 8 === 0) ? bit + 15 : bit - 1;
    }
  }
  if (isSigned && (val & (1n << BigInt(length - 1)))) val -= 1n << BigInt(length);
  return Number(val);
}
function decodeSig(sig, data) {
  const raw = extractRaw(data, sig.start, sig.length, sig.byte_order, sig.is_signed);
  const scale = sig.scale || 1;
  const value = Math.round((raw * scale + sig.offset) * 1e6) / 1e6;
  return [value, raw];
}
function decodeMessage(msg, data) {
  const out = {};
  let selector = null;
  for (const sig of msg.signals) {
    if (!sig.is_mux) continue;
    try { const pair = decodeSig(sig, data); out[sig.name] = pair; selector = pair[1]; }
    catch (e) { /* 截断帧忽略该信号 */ }
  }
  for (const sig of msg.signals) {
    if (sig.is_mux) continue;
    if (sig.mux && (selector === null || !sig.mux.includes(selector))) continue;
    try { out[sig.name] = decodeSig(sig, data); } catch (e) { /* 截断帧忽略该信号 */ }
  }
  return out;
}
function buildIndexes(messages) {
  const byIdExt = new Map(), byId = new Map();
  for (const m of messages) {
    const k = m.id + "|" + !!m.extended;
    if (!byIdExt.has(k)) byIdExt.set(k, m);
    if (!byId.has(m.id)) byId.set(m.id, m);
  }
  return { byIdExt, byId };
}
function lookupMsg(idx, id, ext) {
  return idx.byIdExt.get(id + "|" + !!ext) || idx.byId.get(id) || null;
}

function parseIdToken(tok) {
  let ext = false;
  let s = String(tok || "").trim();
  if (/x$/i.test(s)) { ext = true; s = s.slice(0, -1); }
  if (/^0x/i.test(s)) s = s.slice(2);
  if (s.startsWith("#")) { ext = true; s = s.slice(1); }
  const id = parseInt(s, 16);
  if (!Number.isFinite(id)) return null;
  if (id > 0x7ff) ext = true;
  return { id: id & 0x1fffffff, ext };
}
function bytesFromHexTokens(tokens) {
  const out = [];
  for (const t of tokens) {
    if (!/^[0-9A-Fa-f]{2}$/.test(t)) break;
    out.push(parseInt(t, 16));
  }
  return Uint8Array.from(out);
}
function bytesFromHexString(s) {
  const h = cleanData(s);
  const out = [];
  for (let i = 0; i + 1 < h.length; i += 2) {
    if (!/^[0-9A-Fa-f]{2}$/.test(h.slice(i, i + 2))) break;
    out.push(parseInt(h.slice(i, i + 2), 16));
  }
  return Uint8Array.from(out);
}

function parseASC(text) {
  const out = [];
  for (const raw of String(text || "").replace(/\r/g, "").split("\n")) {
    const line = raw.trim();
    if (!line || /^(date|base|internal events|Begin|End)/i.test(line)) continue;
    const tMatch = line.match(/^([\d.]+)\s+(.*)$/);
    if (!tMatch) continue;
    const ts = Number(tMatch[1]);
    const rest = tMatch[2];
    const tok = rest.split(/\s+/);
    try {
      if (/^CANFD\b/i.test(rest)) {
        // tMatch 已取走时间戳：CANFD ch dir id brs esi dlc_code byte_len data...
        const idp = parseIdToken(tok[3]);
        if (!idp) continue;
        const lenToken = tok[7];
        const dataStart = /^\d+$/.test(lenToken || "") ? 8 : 7;
        const data = bytesFromHexTokens(tok.slice(dataStart));
        const dlc = /^\d+$/.test(lenToken || "") ? Number(lenToken) : data.length;
        out.push({
          timestamp: ts, ch: String(Number(tok[1]) - 1 || 0), id: idp.id, ext: idp.ext,
          fd: true, brs: tok[4] === "1", esi: tok[5] === "1",
          dlc: Math.min(dlc || data.length, 64), data,
        });
      } else if (tok.length >= 6 && /^[dDrR]$/.test(tok[3])) {
        // ch id dir d|r dlc data...
        const idp = parseIdToken(tok[1]);
        if (!idp) continue;
        const data = bytesFromHexTokens(tok.slice(5));
        out.push({
          timestamp: ts, ch: String(Number(tok[0]) - 1 || 0), id: idp.id, ext: idp.ext,
          fd: false, brs: false, esi: false, dlc: data.length, data,
          remote: tok[3].toLowerCase() === "r",
        });
      }
    } catch (e) { /* 跳过异常行 */ }
  }
  return out;
}

function parseTRC(text) {
  const out = [];
  for (const raw of String(text || "").replace(/\r/g, "").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith(";")) continue;
    const tok = line.split(/\s+/);
    if (tok.length < 9 || !/^\d+$/.test(tok[0])) continue;
    try {
      const id = parseInt(tok[4], 16);
      if (!Number.isFinite(id)) continue;
      const fd = /^FB$/i.test(tok[2]);
      const data = bytesFromHexString(tok[8]);
      out.push({
        timestamp: Number(tok[1]) / 1000, ch: String(Number(tok[3]) - 1 || 0),
        id: id & 0x1fffffff, ext: id > 0x7ff || tok[4].toUpperCase().endsWith("X"),
        fd, brs: false, esi: false, dlc: data.length, data,
        remote: false, error: /^ER$/i.test(tok[2]),
      });
    } catch (e) { /* 跳过异常行 */ }
  }
  return out;
}

async function inflateBytes(u8) {
  if (typeof DecompressionStream === "undefined") throw new Error("当前浏览器不支持 BLF 解压（需要 DecompressionStream）");
  const attempts = ["deflate", "deflate-raw"];
  let last = null;
  for (const type of attempts) {
    try {
      const stream = new Blob([u8]).stream().pipeThrough(new DecompressionStream(type));
      return new Uint8Array(await new Response(stream).arrayBuffer());
    } catch (e) { last = e; }
  }
  throw last || new Error("BLF 解压失败");
}
function asciiAt(bytes, pos, len) {
  let s = "";
  for (let i = 0; i < len; i++) s += String.fromCharCode(bytes[pos + i] || 0);
  return s;
}
function indexOfBytes(bytes, needle, start, end) {
  outer: for (let i = start; i <= end - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}
function systemTimeToSeconds(dv, off) {
  const y = dv.getUint16(off, true), mo = dv.getUint16(off + 2, true), d = dv.getUint16(off + 6, true);
  const h = dv.getUint16(off + 8, true), mi = dv.getUint16(off + 10, true), s = dv.getUint16(off + 12, true), ms = dv.getUint16(off + 14, true);
  if (!y || !mo || !d) return 0;
  return Date.UTC(y, mo - 1, d, h, mi, s, ms) / 1000;
}
function parseBlfContainer(buf, startTs, out) {
  const bytes = new Uint8Array(buf), dv = new DataView(buf);
  const LOBJ = [0x4c, 0x4f, 0x42, 0x4a];
  let pos = 0;
  while (pos + 16 <= bytes.length) {
    const found = indexOfBytes(bytes, LOBJ, pos, Math.min(bytes.length, pos + 8));
    if (found < 0) break;
    pos = found;
    const headerSize = dv.getUint16(pos + 4, true);
    const headerVersion = dv.getUint16(pos + 6, true);
    const objSize = dv.getUint32(pos + 8, true);
    const objType = dv.getUint32(pos + 12, true);
    const next = pos + objSize;
    if (next > bytes.length || objSize < 16) break;
    let p = pos + 16;
    let flags = 0, ticks = 0;
    if (headerVersion === 1) {
      if (p + 16 > next) { pos = next; continue; }
      flags = dv.getUint32(p, true);
      const lo = dv.getUint32(p + 8, true), hi = dv.getUint32(p + 12, true);
      ticks = Number((BigInt(hi) << 32n) | BigInt(lo));
      p += 16;
    } else if (headerVersion === 2) {
      if (p + 24 > next) { pos = next; continue; }
      flags = dv.getUint32(p, true);
      const lo = dv.getUint32(p + 8, true), hi = dv.getUint32(p + 12, true);
      ticks = Number((BigInt(hi) << 32n) | BigInt(lo));
      p += 24;
    } else { pos = next; continue; }
    const factor = flags === 1 ? 1e-5 : 1e-9;
    const ts = startTs + ticks * factor;
    const idWord = p + 4 <= next ? dv.getUint32(p + 4, true) : 0;
    const id = idWord & 0x1fffffff, ext = !!(idWord & 0x80000000);
    if (objType === 1 || objType === 86) {
      if (p + 16 > next) { pos = next; continue; }
      const ch = dv.getUint16(p, true), f = dv.getUint8(p + 2), dlc = dv.getUint8(p + 3);
      out.push({ timestamp: ts, ch: String(ch - 1), id, ext, fd: false, brs: false, esi: false,
        dlc, data: bytes.slice(p + 8, p + 8 + Math.min(dlc, 8)), remote: !!(f & 0x80) });
    } else if (objType === 100) {
      if (p + 84 > next) { pos = next; continue; }
      const ch = dv.getUint16(p, true), f = dv.getUint8(p + 2), dlcCode = dv.getUint8(p + 3);
      // python-can: <HBBLLBBB5x64s>，字段6/7 为 FD flags/valid bytes，data 从 p+20 开始
      const fdFlags = dv.getUint8(p + 13), valid = dv.getUint8(p + 14);
      out.push({ timestamp: ts, ch: String(ch - 1), id, ext, fd: !!(fdFlags & 0x1),
        brs: !!(fdFlags & 0x2), esi: !!(fdFlags & 0x4), dlc: DLC_LEN[dlcCode] || valid,
        data: bytes.slice(p + 20, p + 20 + Math.min(valid, 64)), remote: !!(f & 0x80) });
    } else if (objType === 101) {
      if (p + 40 > next) { pos = next; continue; }
      const ch = dv.getUint8(p), dlcCode = dv.getUint8(p + 1), valid = dv.getUint8(p + 2);
      const flags64 = dv.getUint32(p + 12, true);
      const dir = dv.getUint8(p + 34), extOff = dv.getUint8(p + 35);
      const dataLen = Math.min(valid, Math.max(0, (extOff || objSize) - headerSize - 40));
      out.push({ timestamp: ts, ch: String(ch - 1), id, ext, fd: !!(flags64 & 0x1000),
        brs: !!(flags64 & 0x2000), esi: !!(flags64 & 0x4000), dlc: DLC_LEN[dlcCode] || valid,
        data: bytes.slice(p + 40, p + 40 + dataLen), remote: !!(flags64 & 0x10) || !!(dir & 1) });
    }
    pos = next;
  }
}
async function parseBLF(buf) {
  const bytes = new Uint8Array(buf), dv = new DataView(buf);
  if (asciiAt(bytes, 0, 4) !== "LOGG") throw new Error("BLF 文件头无效");
  const headerSize = dv.getUint32(4, true);
  const startTs = systemTimeToSeconds(dv, 40);
  const out = [];
  let pos = headerSize || 144;
  while (pos + 16 <= bytes.length) {
    if (asciiAt(bytes, pos, 4) !== "LOBJ") break;
    const objSize = dv.getUint32(pos + 8, true);
    const objType = dv.getUint32(pos + 12, true);
    if (objSize < 16) break;
    const payload = bytes.slice(pos + 16, pos + objSize);
    pos += objSize + (objSize % 4);
    if (objType !== 10 || payload.length < 16) continue;
    const pDv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    const method = pDv.getUint16(0, true);
    const compressed = payload.slice(16);
    let container = null;
    if (method === 0) container = compressed;
    else if (method === 2) container = await inflateBytes(compressed);
    if (container) parseBlfContainer(container.buffer, startTs, out);
  }
  return out;
}

function lowerBound(arr, t) {
  let lo = 0, hi = arr.length;
  while (lo < hi) { const m = (lo + hi) >> 1; if (arr[m] < t) lo = m + 1; else hi = m; }
  return lo;
}
function upperBound(arr, t) {
  let lo = 0, hi = arr.length;
  while (lo < hi) { const m = (lo + hi) >> 1; if (arr[m] <= t) lo = m + 1; else hi = m; }
  return lo;
}
function buildSession(messages, rawFrames, dbcName, logName, logType, warnings) {
  const idx = buildIndexes(messages);
  rawFrames.sort((a, b) => a.timestamp - b.timestamp);
  const t0 = rawFrames.length ? rawFrames[0].timestamp : 0;
  const frames = [], msgFrames = {}, msgCounts = {};
  const channels = new Set();
  const stats = {
    total: 0, defined: 0, undefined: 0, fd: 0, std: 0, ext: 0,
    error_frame: 0, remote: 0, decode_err: 0, truncated: false,
    duration: 0, msg_count: messages.length,
    sig_count: messages.reduce((n, m) => n + m.signals.length, 0),
  };
  for (const r of rawFrames) {
    if (frames.length >= MAX_FRAMES) { stats.truncated = true; warnings.push("帧数超过上限，已截断"); break; }
    const id = Number(r.id) & 0x1fffffff, ext = !!r.ext;
    const data = r.data instanceof Uint8Array ? r.data : bytesFromHexString(r.data);
    const t = Math.round((r.timestamp - t0) * 1e6) / 1e6;
    const rec = {
      i: frames.length, t, ts: Math.round(r.timestamp * 1e6) / 1e6,
      ch: r.ch == null ? "" : String(r.ch), id, id_hex: hexId(id), ext,
      fd: !!r.fd, brs: !!r.brs, esi: !!r.esi, dlc: data.length,
      data: Array.from(data, b => b.toString(16).toUpperCase().padStart(2, "0")).join(" "),
      msg: null, sigs: {}, error: !!r.error, remote: !!r.remote,
    };
    if (rec.fd) stats.fd++;
    if (rec.ext) stats.ext++; else stats.std++;
    if (rec.error) stats.error_frame++;
    if (rec.remote) stats.remote++;
    if (rec.ch) channels.add(rec.ch);
    const msg = lookupMsg(idx, id, ext);
    if (msg) {
      rec.msg = msg.name;
      stats.defined++;
      msgCounts[rec.id_hex] = (msgCounts[rec.id_hex] || 0) + 1;
      try {
        rec.sigs = decodeMessage(msg, data);
      } catch (e) {
        stats.decode_err++;
        if (warnings.length < 10) warnings.push(rec.id_hex + " 解码失败: " + e.message);
      }
    } else stats.undefined++;
    frames.push(rec);
    if (rec.msg) (msgFrames[rec.msg] || (msgFrames[rec.msg] = [])).push(rec);
  }
  stats.total = frames.length;
  stats.duration = frames.length ? frames[frames.length - 1].t : 0;
  const meta = {
    dbc: dbcName, log: logName, log_type: logType, messages, stats, warnings,
    channels: Array.from(channels).sort(), msg_counts: msgCounts,
  };
  return { meta, frames, t_list: frames.map(f => f.t), msg_frames: msgFrames, msg_counts: msgCounts, byIndex: idx };
}

function parseSignalDef(j, defaultComment) {
  const name = String(j.name || "").trim();
  if (!name) throw new Error("请填写信号名");
  if (name.includes("|")) throw new Error("信号名不能包含 |");
  const start = Number(j.start), length = Number(j.length);
  const scale = Number(j.scale === "" || j.scale == null ? 1 : j.scale);
  const offset = Number(j.offset === "" || j.offset == null ? 0 : j.offset);
  if (!Number.isInteger(start) || start < 0 || start > 512) throw new Error("起始位需在 0~512");
  if (!Number.isInteger(length) || length < 1 || length > 64) throw new Error("长度需在 1~64");
  if (!scale) throw new Error("Factor 不能为 0");
  const numOrNull = v => (v === "" || v == null) ? null : (Number.isFinite(Number(v)) ? Number(v) : null);
  return {
    name, start, length,
    byte_order: j.byte_order === "big_endian" ? "big_endian" : "little_endian",
    is_signed: !!j.is_signed, scale, offset,
    unit: String(j.unit || "").trim(), min: numOrNull(j.min), max: numOrNull(j.max),
    choices: parseChoices(j.choices), mux: null, is_mux: false,
    comment: String(j.comment || "").trim() || defaultComment || "自定义信号", custom: true,
  };
}
function refreshStats(s) {
  s.meta.stats.msg_count = s.meta.messages.length;
  s.meta.stats.sig_count = s.meta.messages.reduce((n, m) => n + m.signals.length, 0);
  s.meta.stats.defined = s.frames.filter(f => f.msg).length;
  s.msg_frames = {};
  for (const f of s.frames) if (f.msg) (s.msg_frames[f.msg] || (s.msg_frames[f.msg] = [])).push(f);
}
function addSignal(s, j) {
  const sig = parseSignalDef(j, "自定义信号");
  let target = null;
  if (j.custom_msg) {
    const raw = String(j.can_id || "").trim();
    const id = /^0x/i.test(raw) ? parseInt(raw.slice(2), 16) : parseInt(raw, 16);
    if (!Number.isFinite(id) || id < 0 || id > 0x1fffffff) throw new Error("CAN ID 格式错误");
    const ext = !!j.extended;
    target = s.meta.messages.find(m => m.id === id && m.extended === ext);
    if (!target) {
      target = { id, id_hex: hexId(id), name: String(j.msg_name || "").trim() || ("CUSTOM_" + hexId(id)),
        dlc: Math.max(1, Math.min(64, Number(j.dlc) || 8)), extended: ext, cycle_time: null,
        comment: "自定义报文", signals: [] };
      s.meta.messages.push(target); s.meta.messages.sort((a, b) => a.id - b.id);
    }
  } else {
    target = s.meta.messages.find(m => m.name === j.msg_name);
    if (!target) throw new Error("目标报文不存在");
  }
  if (target.signals.some(x => x.name === sig.name)) throw new Error("该报文中已存在同名信号");
  target.signals.push(sig);
  let decoded = 0;
  for (const f of s.frames) {
    const hit = j.custom_msg ? (f.id === target.id && f.ext === target.extended) : (f.msg === target.name);
    if (!hit) continue;
    if (j.custom_msg) f.msg = target.name;
    const data = bytesFromHexString(f.data);
    try { f.sigs[sig.name] = decodeSig(sig, data); decoded++; } catch (e) { /* 超出长度 */ }
  }
  s.byIndex = buildIndexes(s.meta.messages);
  refreshStats(s);
  s.msg_counts[target.id_hex] = (s.msg_counts[target.id_hex] || 0) + decoded;
  return { ok: true, msg: target.name, signal: sig, decoded, messages: s.meta.messages, stats: s.meta.stats };
}
function editSignal(s, j) {
  const target = s.meta.messages.find(m => m.name === j.msg_name);
  if (!target) throw new Error("目标报文不存在");
  const idx = target.signals.findIndex(x => x.name === j.old_name);
  if (idx < 0) throw new Error("信号不存在");
  const old = target.signals[idx];
  const sig = parseSignalDef(j, old.comment || "");
  sig.mux = old.mux; sig.is_mux = old.is_mux; sig.custom = old.custom;
  if (sig.name !== old.name && target.signals.some(x => x.name === sig.name)) throw new Error("该报文中已存在同名信号");
  target.signals[idx] = sig;
  let decoded = 0;
  for (const f of s.frames) {
    if (f.msg !== target.name || !(old.name in f.sigs)) continue;
    const data = bytesFromHexString(f.data);
    try {
      const pair = decodeSig(sig, data);
      delete f.sigs[old.name]; f.sigs[sig.name] = pair; decoded++;
    } catch (e) { delete f.sigs[old.name]; }
  }
  s.byIndex = buildIndexes(s.meta.messages);
  refreshStats(s);
  return { ok: true, msg: target.name, old_name: old.name, signal: sig, decoded, messages: s.meta.messages };
}
function deleteSignal(s, j) {
  const target = s.meta.messages.find(m => m.name === j.msg_name);
  if (!target) throw new Error("目标报文不存在");
  const before = target.signals.length;
  target.signals = target.signals.filter(x => x.name !== j.sig_name);
  if (target.signals.length === before) throw new Error("信号不存在");
  let removed = 0;
  for (const f of s.frames) if (f.msg === target.name && (j.sig_name in f.sigs)) { delete f.sigs[j.sig_name]; removed++; }
  refreshStats(s);
  return { ok: true, msg: target.name, sig: j.sig_name, removed, messages: s.meta.messages, stats: s.meta.stats };
}
function queryFrames(s, o) {
  let frames = s.frames;
  if (o.msg) frames = frames.filter(f => f.msg === o.msg || f.id_hex.toLowerCase() === String(o.msg).toLowerCase());
  const q = String(o.q || "").trim().toLowerCase();
  if (q) frames = frames.filter(f => {
    if (f.id_hex.toLowerCase().includes(q) || f.data.toLowerCase().includes(q)) return true;
    if (f.msg && f.msg.toLowerCase().includes(q)) return true;
    for (const [name, pair] of Object.entries(f.sigs)) {
      if (name.toLowerCase().includes(q) || String(pair[0]).toLowerCase().includes(q)) return true;
    }
    return false;
  });
  return { ok: true, total: frames.length, offset: o.offset, limit: o.limit, frames: frames.slice(o.offset, o.offset + o.limit) };
}
function framesAround(s, t, span, limit, watchMsgs) {
  const lo = lowerBound(s.t_list, t - span), hi = upperBound(s.t_list, t + span);
  let idxs = [];
  for (let i = lo; i < hi; i++) idxs.push(i);
  idxs.sort((a, b) => Math.abs(s.t_list[a] - t) - Math.abs(s.t_list[b] - t));
  idxs = idxs.slice(0, limit); idxs.sort((a, b) => a - b);
  const watch = {};
  for (const msg of watchMsgs || []) {
    const cand = s.msg_frames[msg];
    if (!cand || !cand.length) continue;
    const ct = cand.map(f => f.t);
    let j = lowerBound(ct, t), best = j < cand.length ? cand[j] : null;
    if (j > 0 && (!best || Math.abs(cand[j - 1].t - t) < Math.abs(best.t - t))) best = cand[j - 1];
    if (best) watch[msg] = best;
  }
  return { ok: true, t, frames: idxs.map(i => s.frames[i]), watch };
}
function series(s, msg, sig, maxPoints) {
  const pts = [];
  for (const f of s.frames) if (f.msg === msg && (sig in f.sigs)) pts.push([f.t, f.sigs[sig][0]]);
  if (!pts.length) return { ok: true, msg, sig, points: [], count: 0, min: null, max: null, avg: null, unit: "" };
  let unit = "";
  const m = s.meta.messages.find(x => x.name === msg);
  if (m) { const sg = m.signals.find(x => x.name === sig); if (sg) unit = sg.unit || ""; }
  const count = pts.length, max = Math.min(20000, Math.max(100, Number(maxPoints) || 6000));
  let reduced = pts;
  if (count > max) {
    const buckets = Math.max(2, Math.floor(max / 2)), step = count / buckets;
    reduced = [];
    for (let b = 0; b < buckets; b++) {
      const a = Math.floor(b * step), z = Math.min(count, Math.floor((b + 1) * step));
      if (a >= z) continue;
      const chunk = pts.slice(a, z);
      let mn = chunk[0], mx = chunk[0];
      for (const p of chunk) { if (p[1] < mn[1]) mn = p; if (p[1] > mx[1]) mx = p; }
      reduced.push(mn[0] <= mx[0] ? mn : mx); reduced.push(mn[0] <= mx[0] ? mx : mn);
    }
  }
  const vals = reduced.map(p => p[1]);
  return { ok: true, msg, sig, unit, count, points: reduced,
    min: Math.min(...vals), max: Math.max(...vals), avg: vals.reduce((a, b) => a + b, 0) / vals.length };
}
function exportDbcText(s) {
  const lines = ['VERSION "1.0"', "NS_ :", "BS_:", "BU_: ECU1 ECU2", ""];
  for (const m of s.meta.messages) {
    const name = dbcIdent(m.name, "MSG");
    lines.push("BO_ " + m.id + " " + name + ": " + m.dlc + " ECU1");
    for (const sg of m.signals) {
      const mux = sg.is_mux ? " M" : (sg.mux ? " m" + sg.mux[0] : "");
      const mn = sg.min == null ? (sg.is_signed ? -(2 ** (sg.length - 1)) : 0) : sg.min;
      const mx = sg.max == null ? ((sg.is_signed ? 2 ** (sg.length - 1) : 2 ** sg.length) - 1) : sg.max;
      lines.push(' SG_ ' + dbcIdent(sg.name, "SIG") + mux + " : " + sg.start + "|" + sg.length +
        "@" + (sg.byte_order === "little_endian" ? "1" : "0") + (sg.is_signed ? "-" : "+") +
        " (" + dbcNum(sg.scale) + "," + dbcNum(sg.offset) + ") [" + dbcNum(mn) + "|" + dbcNum(mx) +
        '] "' + dbcQuote(sg.unit) + '" ECU2');
    }
    lines.push("");
  }
  for (const m of s.meta.messages) {
    const name = dbcIdent(m.name, "MSG");
    if (m.comment) lines.push('CM_ BO_ ' + m.id + ' "' + dbcQuote(m.comment) + '";');
    for (const sg of m.signals) {
      const sn = dbcIdent(sg.name, "SIG");
      if (sg.comment) lines.push('CM_ SG_ ' + m.id + " " + sn + ' "' + dbcQuote(sg.comment) + '";');
      const choices = sg.choices || {};
      const keys = Object.keys(choices);
      if (keys.length) lines.push("VAL_ " + m.id + " " + sn + " " + keys.map(k => k + ' "' + dbcQuote(choices[k]) + '"').join(" ") + " ;");
    }
  }
  return lines.join("\n") + "\n";
}
function exportCsvText(s, msg) {
  let frames = s.frames;
  if (msg) frames = frames.filter(f => f.msg === msg || f.id_hex.toLowerCase() === String(msg).toLowerCase());
  const sigCols = [], seen = new Set();
  if (msg) {
    const m = s.meta.messages.find(x => x.name === msg || x.id_hex.toLowerCase() === String(msg).toLowerCase());
    if (m) for (const sg of m.signals) { sigCols.push([sg.name, sg.unit]); seen.add(sg.name); }
  }
  if (!sigCols.length) for (const f of frames) for (const name of Object.keys(f.sigs)) if (!seen.has(name)) { seen.add(name); sigCols.push([name, ""]); }
  const rows = [["index", "time_rel_s", "time_abs", "channel", "id_hex", "message", "canfd", "brs", "esi", "extended", "dlc", "data_hex"]];
  rows[0].push(...sigCols.flatMap(([name, unit]) => [unit ? name + " [" + unit + "]" : name, name + "_raw"]));
  for (const f of frames) {
    const row = [f.i, f.t, f.ts, f.ch, f.id_hex, f.msg || "", f.fd ? 1 : 0, f.brs ? 1 : 0, f.esi ? 1 : 0, f.ext ? 1 : 0, f.dlc, f.data];
    for (const [name] of sigCols) { const p = f.sigs[name]; row.push(p ? p[0] : "", p ? p[1] : ""); }
    rows.push(row);
  }
  return "\uFEFF" + rows.map(r => r.map(v => {
    const x = String(v == null ? "" : v);
    return /[",\n]/.test(x) ? '"' + x.replace(/"/g, '""') + '"' : x;
  }).join(",")).join("\r\n");
}
function downloadText(text, filename, mime) {
  const blob = new Blob([text], { type: mime || "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 3000);
}

const Local = {
  session: null,
  async load(dbcFile, logFile) {
    if (!logFile) throw new Error("请选择日志文件（DBC 可不选）");
    const ext = String(logFile.name || "").split(".").pop().toLowerCase();
    if (!["asc", "blf", "trc"].includes(ext)) throw new Error("日志格式仅支持 ASC / BLF / TRC");
    let messages = [];
    let dbcName = "auto_generated.dbc";
    if (dbcFile && dbcFile.name) {
      dbcName = dbcFile.name;
      messages = parseDbc(decodeDbcText(await dbcFile.arrayBuffer()));
    }
    const warnings = [];
    let raw = [];
    if (ext === "asc") raw = parseASC(await logFile.text());
    else if (ext === "trc") raw = parseTRC(await logFile.text());
    else raw = await parseBLF(await logFile.arrayBuffer());
    if (!raw.length) warnings.push("未解析到 CAN 报文，请检查日志格式");
    this.session = buildSession(messages, raw, dbcName, logFile.name, ext.toUpperCase(), warnings);
    return {
      ok: true, sid: "local", meta: this.session.meta,
      frames: this.session.frames, warnings: this.session.meta.warnings,
    };
  },
  queryFrames(o) { return queryFrames(this.session, o); },
  framesAround(t, span, limit, watchMsgs) { return framesAround(this.session, t, span, limit, watchMsgs); },
  series(msg, sig, maxPoints) { return series(this.session, msg, sig, maxPoints); },
  addSignal(j) { return addSignal(this.session, j); },
  editSignal(j) { return editSignal(this.session, j); },
  deleteSignal(j) { return deleteSignal(this.session, j); },
  exportDbc() { downloadText("\uFEFF" + exportDbcText(this.session), "export.dbc", "application/octet-stream"); },
  exportCsv(msg) { downloadText(exportCsvText(this.session, msg), "decoded_signals.csv", "text/csv;charset=utf-8"); },
};

global.DbcLocal = Local;
global.DbcParsers = { parseDbc, decodeDbcText, parseASC, parseTRC, parseBLF, exportDbcText, exportCsvText };
})(window);
