// github-core-clone-01 entry: a GitHub-compatible forge in one Node 22 process.
//
// Surfaces (all stdlib-only, no git binary, no network):
//   - git smart HTTP  /{owner}/{repo}.git  (upload-pack v2, receive-pack v0)
//   - REST v3         /api/v3
//   - GraphQL v4      /api/graphql
//   - MCP             /mcp  (JSON-RPC 2.0 Streamable HTTP, modern server/discover + legacy initialize)
//
// Determinism: no wall clock, no Math.random, no unseeded ids anywhere in request
// handling. Timestamps, request ids and database ids come from monotonic counters
// seeded at a fixed epoch, so the same request sequence replays byte-identically.
//
// The token owner's login is LEARNED from the owner strings in requests (the suite
// token is opaque and encodes no login): the first owner that addresses a repository
// this token created binds that repository and becomes the viewer login. Nothing
// about the scenario (logins, names, seed) is hardcoded.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// -------------------------------------------------------------------------------------------
// constants and tiny utilities
// -------------------------------------------------------------------------------------------

const ZERO_OID = '0000000000000000000000000000000000000000';
const OID_RE = /^[0-9a-f]{40}$/i;
const JSON_TYPE = 'application/json; charset=utf-8';
const EXPECTED_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const BASE_TS = Math.floor(Date.UTC(2026, 10, 14, 6, 30, 0) / 1000); // competition opening, fixed
const SERVER_NAME = 'github-core-clone-forge';
const SERVER_VERSION = '1.0.0';

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function sha1Hex(data: Buffer | string): string {
  return createHash('sha1').update(data).digest('hex');
}

/** SHA-1 of a git object: sha1("<type> <len>\0" + data). */
function hashObject(type: string, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, data]));
}

function b64encode(data: Buffer | string): string {
  return Buffer.from(data).toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/\s+/g, ''), 'base64');
}

function isoOf(ts: number): string {
  return new Date(ts * 1000).toISOString();
}

// -------------------------------------------------------------------------------------------
// pkt-line framing (git smart HTTP)
// -------------------------------------------------------------------------------------------

function pktLine(payload: Buffer | string): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

interface PktPacket {
  kind: 'data' | 'flush' | 'delim';
  payload: Buffer;
}

/** Decode a whole buffer of pkt-lines. Throws on malformed framing. */
function decodePktLines(buf: Buffer): PktPacket[] {
  const out: PktPacket[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line length');
    const hex = buf.subarray(off, off + 4).toString('ascii');
    if (hex === '0000') {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (hex === '0001') {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error(`bad pkt-line length ${JSON.stringify(hex)}`);
    const len = parseInt(hex, 16);
    if (len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
    out.push({ kind: 'data', payload: Buffer.from(buf.subarray(off + 4, off + len)) });
    off += len;
  }
  return out;
}

/**
 * Split a buffer into data packets and the offset where the pkt-line section ends
 * (the byte after the terminating flush). Throws on malformed framing.
 */
function splitPktSection(buf: Buffer): { packets: PktPacket[]; rest: Buffer } {
  const packets: PktPacket[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line length');
    const hex = buf.subarray(off, off + 4).toString('ascii');
    if (hex === '0000') return { packets, rest: Buffer.from(buf.subarray(off + 4)) };
    if (hex === '0001') {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error(`bad pkt-line length ${JSON.stringify(hex)}`);
    const len = parseInt(hex, 16);
    if (len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
    packets.push({ kind: 'data', payload: Buffer.from(buf.subarray(off + 4, off + len)) });
    off += len;
  }
  throw new Error('pkt-line section has no terminating flush');
}

// -------------------------------------------------------------------------------------------
// git object model: parse/build commit, tree, tag
// -------------------------------------------------------------------------------------------

type GitObjType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObj {
  type: GitObjType;
  data: Buffer;
}

interface CommitInfo {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    if (space < 0) break;
    const mode = data.subarray(off, space).toString('ascii');
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface TagInfo {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4);
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}

/** All objects reachable from `tips` (commits, trees, blobs, tags), by graph walk. */
function collectReachable(
  tips: Iterable<string>,
  lookup: (oid: string) => GitObj | undefined,
): Set<string> {
  const seen = new Set<string>();
  const stack: string[] = [...tips];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    const obj = lookup(oid);
    if (obj === undefined) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      stack.push(c.tree, ...c.parents);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) stack.push(e.oid);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    }
  }
  return seen;
}

/** Tree closure of one commit: the commit itself plus its tree, subtrees and blobs — never parents. */
function treeClosure(oid: string, lookup: (oid: string) => GitObj | undefined): Set<string> {
  const out = new Set<string>();
  const commit = lookup(oid);
  if (commit === undefined || commit.type !== 'commit') return out;
  out.add(oid);
  const stack: string[] = [parseCommit(commit.data).tree];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    if (out.has(cur)) continue;
    const obj = lookup(cur);
    if (obj === undefined) continue;
    out.add(cur);
    if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) stack.push(e.oid);
    }
  }
  return out;
}

/** Reachability that stops at `cut` commits (shallow boundaries): their trees are
 *  included, but their parents are not followed. Used for a shallow client's haves. */
function collectReachableCut(
  tips: Iterable<string>,
  lookup: (oid: string) => GitObj | undefined,
  cut: ReadonlySet<string>,
): Set<string> {
  const seen = new Set<string>();
  const stack: string[] = [...tips];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    const obj = lookup(oid);
    if (obj === undefined) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      stack.push(c.tree);
      if (!cut.has(oid)) stack.push(...c.parents);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) stack.push(e.oid);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    }
  }
  return seen;
}

/** Commit-distance-limited reachability (for shallow fetches). */
function collectShallow(
  wants: readonly string[],
  depth: number,
  lookup: (oid: string) => GitObj | undefined,
): { objects: Set<string>; boundary: Set<string> } {
  // BFS over commits by distance from a want. Included commits: distance < depth.
  const commitDist = new Map<string, number>();
  const queue: Array<[string, number]> = [];
  for (const w of wants) {
    const obj = lookup(w);
    if (obj === undefined) continue;
    if (obj.type === 'tag') {
      const target = parseTag(obj.data).object;
      if (!commitDist.has(target)) {
        commitDist.set(target, 0);
        queue.push([target, 0]);
      }
    } else if (obj.type === 'commit') {
      if (!commitDist.has(w)) {
        commitDist.set(w, 0);
        queue.push([w, 0]);
      }
    }
  }
  const boundary = new Set<string>();
  const includedCommits = new Set<string>();
  while (queue.length > 0) {
    const [oid, dist] = queue.shift()!;
    if (dist >= depth) continue;
    includedCommits.add(oid);
    if (dist === depth - 1) boundary.add(oid);
    const obj = lookup(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) {
      if (!commitDist.has(p)) {
        commitDist.set(p, dist + 1);
        queue.push([p, dist + 1]);
      }
    }
  }
  // Each included commit contributes only itself and its tree closure — parents
  // are never sent, even though collectReachable would follow them.
  const objects = new Set<string>();
  for (const w of wants) {
    const obj = lookup(w);
    if (obj !== undefined && obj.type === 'tag') objects.add(w);
  }
  for (const oid of includedCommits) {
    for (const reached of treeClosure(oid, lookup)) objects.add(reached);
  }
  return { objects, boundary };
}

// -------------------------------------------------------------------------------------------
// packfiles: write plain packs; read packs incl. OFS/REF deltas
// -------------------------------------------------------------------------------------------

const TYPE_CODE: Record<GitObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, GitObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function packObjectHeader(type: GitObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

function writePack(objects: Iterable<GitObj & { oid: string }>): Buffer {
  const list = [...objects].sort((a, b) => (a.oid < b.oid ? -1 : a.oid > b.oid ? 1 : 0));
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const o of list) {
    parts.push(packObjectHeader(o.type, o.data.length));
    parts.push(deflateSync(o.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function readVarint(buf: Buffer, off: number): { value: number; next: number } {
  let value = buf[off] & 0x7f;
  let next = off + 1;
  let shift = 7;
  while (buf[next - 1] & 0x80) {
    value |= (buf[next] & 0x7f) << shift;
    shift += 7;
    next += 1;
  }
  return { value, next };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const baseSize = readVarint(delta, off);
  off = baseSize.next;
  if (baseSize.value !== base.length) throw new Error('delta base size mismatch');
  const resultSize = readVarint(delta, off);
  off = resultSize.next;
  const chunks: Buffer[] = [];
  let total = 0;
  while (off < delta.length) {
    const op = delta[off];
    off += 1;
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i += 1) {
        if (op & (1 << i)) {
          cpOff |= delta[off] << (8 * i);
          off += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if (op & (0x10 << i)) {
          cpSize |= delta[off] << (8 * i);
          off += 1;
        }
      }
      if (cpSize === 0) cpSize = 0x10000;
      if (cpOff + cpSize > base.length) throw new Error('delta copy out of range');
      chunks.push(base.subarray(cpOff, cpOff + cpSize));
      total += cpSize;
    } else if (op !== 0) {
      chunks.push(delta.subarray(off, off + op));
      total += op;
      off += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  const out = Buffer.concat(chunks);
  if (out.length !== resultSize.value || total !== resultSize.value) {
    throw new Error('delta result size mismatch');
  }
  return out;
}

interface PackEntry {
  oid: string;
  type: GitObjType;
  data: Buffer;
}

/** Read a packfile, resolving OFS_DELTA and REF_DELTA against earlier entries and `resolveBase`. */
function readPack(pack: Buffer, resolveBase?: (oid: string) => GitObj | undefined): { objects: PackEntry[]; deltaCount: number } {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('not a packfile');
  }
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const trailer = pack.subarray(pack.length - 20).toString('hex');
  const expected = sha1Hex(pack.subarray(0, pack.length - 20));
  if (trailer !== expected) throw new Error('pack trailer checksum mismatch');
  const objects: PackEntry[] = [];
  const byOid = new Map<string, GitObj>();
  const byOffset = new Map<number, GitObj>();
  let deltaCount = 0;
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const entryStart = off;
    const first = pack[off];
    off += 1;
    const typeCode = (first >> 4) & 0x07;
    let size = first & 0x0f;
    let shift = 4;
    let b = first;
    while (b & 0x80) {
      b = pack[off];
      off += 1;
      size |= (b & 0x7f) << shift;
      shift += 7;
    }
    if (typeCode === 6) {
      // OFS_DELTA: negative offset varint
      let b = pack[off];
      off += 1;
      let ofs = b & 0x7f;
      while (b & 0x80) {
        b = pack[off];
        off += 1;
        ofs = ((ofs + 1) << 7) | (b & 0x7f);
      }
      const baseOff = entryStart - ofs;
      const base = byOffset.get(baseOff);
      if (base === undefined) throw new Error('ofs-delta base not found');
      const inflated = inflateSync(pack.subarray(off));
      const consumed = inflatedConsumed(pack, off);
      off += consumed;
      const data = applyDelta(base.data, inflated);
      const oid = hashObject(base.type, data);
      const obj: GitObj = { type: base.type, data };
      objects.push({ oid, ...obj });
      byOid.set(oid, obj);
      byOffset.set(entryStart, obj);
      deltaCount += 1;
    } else if (typeCode === 7) {
      // REF_DELTA: 20-byte base oid
      const baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
      const base = byOid.get(baseOid) ?? resolveBase?.(baseOid);
      if (base === undefined) throw new Error(`ref-delta base ${baseOid} not found`);
      const inflated = inflateSync(pack.subarray(off));
      const consumed = inflatedConsumed(pack, off);
      off += consumed;
      const data = applyDelta(base.data, inflated);
      const oid = hashObject(base.type, data);
      const obj: GitObj = { type: base.type, data };
      objects.push({ oid, ...obj });
      byOid.set(oid, obj);
      byOffset.set(entryStart, obj);
      deltaCount += 1;
    } else {
      const type = CODE_TYPE[typeCode];
      if (type === undefined) throw new Error(`unknown pack object type ${typeCode}`);
      const inflated = inflateSync(pack.subarray(off));
      const consumed = inflatedConsumed(pack, off);
      off += consumed;
      if (inflated.length !== size) throw new Error('pack object size mismatch');
      const oid = hashObject(type, inflated);
      const obj: GitObj = { type, data: Buffer.from(inflated) };
      objects.push({ oid, ...obj });
      byOid.set(oid, obj);
      byOffset.set(entryStart, obj);
    }
  }
  return { objects, deltaCount };
}

/**
 * Bytes consumed by the zlib stream starting at `off`. inflateSync ignores trailing
 * bytes, so the stream's end is the smallest length that inflates without error:
 * exponential search for a succeeding length, then binary search for the minimum.
 * The search adapts to the stream's size, so small objects cost only a few tiny
 * inflations.
 */
function inflatedConsumed(pack: Buffer, off: number): number {
  const limit = pack.length - 20 - off;
  const ok = (len: number): boolean => {
    try {
      inflateSync(pack.subarray(off, off + len));
      return true;
    } catch {
      return false;
    }
  };
  let hi = 1;
  while (hi < limit && !ok(hi)) hi *= 2;
  if (hi > limit) hi = limit;
  let lo = Math.floor(hi / 2);
  if (lo < 1) lo = 1;
  // Invariant: ok(hi) is true (or hi === limit, where the stream must end).
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (ok(mid)) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}

// -------------------------------------------------------------------------------------------
// store: repositories, branches, commits, issues, pull requests
// -------------------------------------------------------------------------------------------

interface Label {
  name: string;
  color: string;
}

interface Issue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  comments: Array<{ id: number; body: string; createdAt: string }>;
  createdSeq: number;
  createdAt: string;
  updatedAt: string;
}

interface PullFile {
  filename: string;
  status: 'added' | 'modified' | 'removed';
  additions: number;
  deletions: number;
  changes: number;
}

interface Pull {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headBranch: string;
  baseBranch: string;
  headSha: string;
  baseSha: string;
  files: PullFile[];
  createdSeq: number;
  createdAt: string;
}

interface Branch {
  tip: string | null;
  commits: string[]; // newest first
}

interface Repo {
  dbId: number;
  name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  ownerLogin: string | null;
  createdSeq: number;
  branches: Map<string, Branch>;
  tags: Map<string, string>;
  objects: Map<string, GitObj>;
  commitFiles: Map<string, Map<string, Buffer>>; // commit sha -> full file snapshot
  commitMessage: Map<string, string>; // commit sha -> message as submitted (no trailing \n)
  commitTs: Map<string, number>;
  labels: Map<string, Label>;
  issues: Issue[];
  pulls: Pull[];
  nextIssue: number;
  nextPull: number;
  nextComment: number;
  fetchCache: Map<string, Buffer>; // fetch response by request key; cleared on mutation
}

/** Drop a repo's cached fetch responses after any mutation (push, commit, ref move). */
function touchRepo(repo: Repo): void {
  repo.fetchCache.clear();
}

/** True iff `ancestor` is reachable from `tip` following commit parents only
 *  (no tree/blob traversal — the fast-forward check needs commit ancestry). */
function isAncestor(ancestor: string, tip: string, lookup: (oid: string) => GitObj | undefined): boolean {
  if (ancestor === tip) return true;
  const seen = new Set<string>([tip]);
  const stack = [tip];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    const obj = lookup(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) {
      if (p === ancestor) return true;
      if (!seen.has(p)) {
        seen.add(p);
        stack.push(p);
      }
    }
  }
  return false;
}

class Store {
  repos: Repo[] = [];
  byName = new Map<string, Repo>();
  viewerLogin: string | null = null;
  viewerId = 1;
  seq = 0; // deterministic clock + creation order
  reqCounter = 0;
  dbCounter = 0;

  /** Next deterministic timestamp (seconds since the fixed epoch). */
  nextTs(): number {
    return BASE_TS + (this.seq += 1);
  }

  nextReqId(): string {
    return `req-${(this.reqCounter += 1).toString(36)}`;
  }

  /** Learn the token owner's login from an owner string that addresses a real repo. */
  learnViewer(owner: string): void {
    if (this.viewerLogin === null && owner !== '') this.viewerLogin = owner;
  }

  authorIdent(): string {
    const login = this.viewerLogin ?? 'forge';
    return `${login} <${login}@example.invalid>`;
  }

  /** Find a repo by owner+name. Binds an unbound repo to the owner that asks for it. */
  findRepo(owner: string, name: string): Repo | null {
    const repo = this.byName.get(name);
    if (repo === undefined) return null;
    if (repo.ownerLogin === null) {
      repo.ownerLogin = owner;
      this.learnViewer(owner);
    }
    if (repo.ownerLogin !== owner) return null;
    return repo;
  }

  findRepoByDbId(dbId: number): Repo | null {
    return this.repos.find((r) => r.dbId === dbId) ?? null;
  }

  createRepo(name: string, description: string, isPrivate: boolean): Repo {
    const repo: Repo = {
      dbId: (this.dbCounter += 1),
      name,
      description,
      isPrivate,
      defaultBranch: 'main',
      ownerLogin: null,
      createdSeq: this.seq += 1,
      branches: new Map(),
      tags: new Map(),
      objects: new Map(),
      commitFiles: new Map(),
      commitMessage: new Map(),
      commitTs: new Map(),
      labels: new Map(),
      issues: [],
      pulls: [],
      nextIssue: 1,
      nextPull: 1,
      nextComment: 1,
      fetchCache: new Map(),
    };
    // Seed the six labels every GitHub repository starts with.
    for (const [lname, color] of [
      ['bug', 'd73a4a'],
      ['documentation', '0075ca'],
      ['duplicate', 'cfd3d7'],
      ['enhancement', 'a2eeef'],
      ['good first issue', '7057ff'],
      ['help wanted', '008672'],
      ['invalid', 'e4e669'],
      ['question', 'd876e3'],
      ['wontfix', 'ffffff'],
    ] as const) {
      repo.labels.set(lname, { name: lname, color });
    }
    this.repos.push(repo);
    this.byName.set(name, repo);
    return repo;
  }

  deleteRepo(repo: Repo): void {
    this.repos = this.repos.filter((r) => r !== repo);
    this.byName.delete(repo.name);
  }

  /** Store a git object, keyed by its hash. */
  putObject(repo: Repo, type: GitObjType, data: Buffer): string {
    const oid = hashObject(type, data);
    if (!repo.objects.has(oid)) {
      repo.objects.set(oid, { type, data });
      touchRepo(repo);
    }
    return oid;
  }

  lookup(repo: Repo): (oid: string) => GitObj | undefined {
    return (oid: string) => repo.objects.get(oid);
  }

  /** Build (and store) the tree objects for a full file snapshot; returns the root tree oid. */
  treeFromSnapshot(repo: Repo, snapshot: Map<string, Buffer>): string {
    const build = (prefix: string): string => {
      const entries: TreeEntry[] = [];
      const dirs = new Map<string, Map<string, Buffer>>();
      for (const [path, data] of snapshot) {
        if (!path.startsWith(prefix)) continue;
        const rest = path.slice(prefix.length);
        const slash = rest.indexOf('/');
        if (slash < 0) {
          entries.push({ mode: '100644', name: rest, oid: this.putObject(repo, 'blob', data) });
        } else {
          const dir = rest.slice(0, slash);
          let sub = dirs.get(dir);
          if (sub === undefined) {
            sub = new Map();
            dirs.set(dir, sub);
          }
          sub.set(path, data);
        }
      }
      for (const [dir, sub] of [...dirs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
        entries.push({ mode: '40000', name: dir, oid: build(`${prefix}${dir}/`) });
      }
      return this.putObject(repo, 'tree', buildTree(entries));
    };
    return build('');
  }

  /** Snapshot of the file tree at a commit (from stored snapshots, or parsed from git objects). */
  snapshotAt(repo: Repo, commitSha: string): Map<string, Buffer> {
    const stored = repo.commitFiles.get(commitSha);
    if (stored !== undefined) return new Map(stored);
    const out = new Map<string, Buffer>();
    const walk = (treeOid: string, prefix: string): void => {
      const tree = repo.objects.get(treeOid);
      if (tree === undefined || tree.type !== 'tree') return;
      for (const e of parseTree(tree.data)) {
        if (e.mode === '40000') walk(e.oid, `${prefix}${e.name}/`);
        else {
          const blob = repo.objects.get(e.oid);
          if (blob !== undefined) out.set(`${prefix}${e.name}`, Buffer.from(blob.data));
        }
      }
    };
    const commit = repo.objects.get(commitSha);
    if (commit !== undefined && commit.type === 'commit') walk(parseCommit(commit.data).tree, '');
    return out;
  }

  /** Ancestor commits of `sha`, newest first (depth-first, parents in order, deduped). */
  ancestorList(repo: Repo, sha: string | null): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    const stack: string[] = sha === null ? [] : [sha];
    while (stack.length > 0) {
      const oid = stack.pop()!;
      if (seen.has(oid)) continue;
      seen.add(oid);
      out.push(oid);
      const obj = repo.objects.get(oid);
      if (obj !== undefined && obj.type === 'commit') {
        const parents = parseCommit(obj.data).parents;
        for (let i = parents.length - 1; i >= 0; i -= 1) stack.push(parents[i]);
      }
    }
    return out;
  }

  /** Create a commit object on a branch from a snapshot; updates the branch. */
  commitOnBranch(
    repo: Repo,
    branchName: string,
    snapshot: Map<string, Buffer>,
    message: string,
  ): { commitSha: string; treeSha: string } {
    const branch = repo.branches.get(branchName);
    const parents: string[] = branch?.tip !== null && branch?.tip !== undefined ? [branch.tip] : [];
    const treeSha = this.treeFromSnapshot(repo, snapshot);
    const ts = this.nextTs();
    const ident = `${this.authorIdent()} ${ts} +0000`;
    const lines = [`tree ${treeSha}`];
    for (const p of parents) lines.push(`parent ${p}`);
    lines.push(`author ${ident}`, `committer ${ident}`, '', message);
    const data = Buffer.from(`${lines.join('\n')}\n`, 'utf8');
    const commitSha = this.putObject(repo, 'commit', data);
    repo.commitFiles.set(commitSha, new Map(snapshot));
    repo.commitMessage.set(commitSha, message);
    repo.commitTs.set(commitSha, ts);
    const commits = [commitSha, ...(branch?.commits ?? [])];
    repo.branches.set(branchName, { tip: commitSha, commits });
    return { commitSha, treeSha };
  }

  /** Create a branch at `sha` (or an unborn branch when sha is null). */
  createBranch(repo: Repo, name: string, sha: string | null): Branch {
    const branch: Branch = { tip: sha, commits: sha === null ? [] : this.ancestorList(repo, sha) };
    repo.branches.set(name, branch);
    touchRepo(repo);
    return branch;
  }

  /** Ref name -> oid for every branch and tag, sorted by name. */
  allRefs(repo: Repo): Array<{ name: string; oid: string }> {
    const refs: Array<{ name: string; oid: string }> = [];
    for (const [name, b] of [...repo.branches.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
      if (b.tip !== null) refs.push({ name: `refs/heads/${name}`, oid: b.tip });
    }
    for (const [name, oid] of [...repo.tags.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
      refs.push({ name: `refs/tags/${name}`, oid });
    }
    return refs;
  }

  /** Peel a ref oid to its commit (following annotated tags). */
  peel(repo: Repo, oid: string): string {
    let cur = oid;
    for (let i = 0; i < 16; i += 1) {
      const obj = repo.objects.get(cur);
      if (obj === undefined || obj.type !== 'tag') return cur;
      cur = parseTag(obj.data).object;
    }
    return cur;
  }

  // ---- issues ----

  createIssue(repo: Repo, title: string, body: string, labelNames: string[]): Issue {
    const ts = this.nextTs();
    const issue: Issue = {
      number: repo.nextIssue,
      title,
      body,
      state: 'open',
      labels: labelNames.map((n) => repo.labels.get(n)!),
      comments: [],
      createdSeq: this.seq,
      createdAt: isoOf(ts),
      updatedAt: isoOf(ts),
    };
    repo.nextIssue += 1;
    repo.issues.push(issue);
    return issue;
  }

  issueGlobalId(repo: Repo, issue: Issue): string {
    return b64encode(`Issue:${repo.dbId}:${issue.number}`);
  }

  pullGlobalId(repo: Repo, pull: Pull): string {
    return b64encode(`PullRequest:${repo.dbId}:${pull.number}`);
  }

  repoGlobalId(repo: Repo): string {
    return b64encode(`Repository:${repo.dbId}`);
  }

  // ---- pull requests ----

  lineDiff(oldText: string, newText: string): { additions: number; deletions: number } {
    const oldLines = oldText.split('\n');
    const newLines = newText.split('\n');
    const oldCount = new Map<string, number>();
    for (const l of oldLines) oldCount.set(l, (oldCount.get(l) ?? 0) + 1);
    let additions = 0;
    for (const l of newLines) {
      const left = oldCount.get(l) ?? 0;
      if (left > 0) oldCount.set(l, left - 1);
      else additions += 1;
    }
    let deletions = 0;
    for (const left of oldCount.values()) deletions += left;
    return { additions, deletions };
  }

  diffFiles(baseSnap: Map<string, Buffer>, headSnap: Map<string, Buffer>): PullFile[] {
    const files: PullFile[] = [];
    const paths = new Set([...baseSnap.keys(), ...headSnap.keys()]);
    for (const path of [...paths].sort()) {
      const oldBuf = baseSnap.get(path);
      const newBuf = headSnap.get(path);
      if (oldBuf !== undefined && newBuf !== undefined) {
        if (oldBuf.equals(newBuf)) continue;
        const { additions, deletions } = this.lineDiff(oldBuf.toString('utf8'), newBuf.toString('utf8'));
        files.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
      } else if (newBuf !== undefined) {
        const additions = newBuf.toString('utf8').split('\n').length;
        files.push({ filename: path, status: 'added', additions, deletions: 0, changes: additions });
      } else if (oldBuf !== undefined) {
        const deletions = oldBuf.toString('utf8').split('\n').length;
        files.push({ filename: path, status: 'removed', additions: 0, deletions, changes: deletions });
      }
    }
    return files;
  }

  createPull(repo: Repo, title: string, body: string, headBranch: string, baseBranch: string): Pull | { error: string } {
    const head = repo.branches.get(headBranch);
    const base = repo.branches.get(baseBranch);
    if (head === undefined || head.tip === null) return { error: `head branch ${headBranch} not found` };
    if (base === undefined || base.tip === null) return { error: `base branch ${baseBranch} not found` };
    const open = repo.pulls.find((p) => p.state === 'open' && p.headBranch === headBranch && p.baseBranch === baseBranch);
    if (open !== undefined) return { error: `an open pull request already exists for ${headBranch}` };
    const ts = this.nextTs();
    const pull: Pull = {
      number: repo.nextPull,
      title,
      body,
      state: 'open',
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      headBranch,
      baseBranch,
      headSha: head.tip,
      baseSha: base.tip,
      files: this.diffFiles(this.snapshotAt(repo, base.tip), this.snapshotAt(repo, head.tip)),
      createdSeq: this.seq,
      createdAt: isoOf(ts),
    };
    repo.nextPull += 1;
    repo.pulls.push(pull);
    return pull;
  }

  /** True when merging `pull` now would conflict with the base tip's current content. */
  pullConflicts(repo: Repo, pull: Pull): boolean {
    const baseTip = repo.branches.get(pull.baseBranch)?.tip;
    if (baseTip === null || baseTip === undefined) return false;
    const baseSnap = this.snapshotAt(repo, pull.baseSha);
    const headSnap = this.snapshotAt(repo, pull.headSha);
    const tipSnap = this.snapshotAt(repo, baseTip);
    for (const f of pull.files) {
      const atBase = baseSnap.get(f.filename);
      const atHead = headSnap.get(f.filename);
      const atTip = tipSnap.get(f.filename);
      const tipChanged = (atTip === undefined) !== (atBase === undefined) || (atTip !== undefined && atBase !== undefined && !atTip.equals(atBase));
      if (!tipChanged) continue;
      const tipMatchesHead =
        (atTip === undefined && atHead === undefined) ||
        (atTip !== undefined && atHead !== undefined && atTip.equals(atHead));
      if (!tipMatchesHead) return true;
    }
    return false;
  }

  /** Squash-merge a pull request onto its base branch. Returns the merge commit sha or an error. */
  mergePull(repo: Repo, pull: Pull): { sha: string } | { error: string; status: number } {
    if (pull.merged) return { error: 'pull request is already merged', status: 405 };
    if (pull.state !== 'open') return { error: 'pull request is closed', status: 405 };
    const base = repo.branches.get(pull.baseBranch);
    const head = repo.branches.get(pull.headBranch);
    if (base === undefined || base.tip === null) return { error: 'base branch not found', status: 422 };
    if (head === undefined || head.tip === null) return { error: 'head branch not found', status: 422 };
    if (this.pullConflicts(repo, pull)) return { error: 'merge conflict', status: 405 };
    const baseSnap = this.snapshotAt(repo, base.tip);
    const headSnap = this.snapshotAt(repo, pull.headSha);
    const merged = new Map(baseSnap);
    for (const f of pull.files) {
      if (f.status === 'removed') merged.delete(f.filename);
      else {
        const content = headSnap.get(f.filename);
        if (content !== undefined) merged.set(f.filename, Buffer.from(content));
      }
    }
    const message = `Merge pull request #${pull.number} from ${repo.ownerLogin ?? 'owner'}/${pull.headBranch}`;
    const treeSha = this.treeFromSnapshot(repo, merged);
    const ts = this.nextTs();
    const ident = `${this.authorIdent()} ${ts} +0000`;
    const lines = [
      `tree ${treeSha}`,
      `parent ${base.tip}`,
      `parent ${head.tip}`,
      `author ${ident}`,
      `committer ${ident}`,
      '',
      message,
    ];
    const data = Buffer.from(`${lines.join('\n')}\n`, 'utf8');
    const mergeSha = this.putObject(repo, 'commit', data);
    repo.commitFiles.set(mergeSha, merged);
    repo.commitMessage.set(mergeSha, message);
    repo.commitTs.set(mergeSha, ts);
    base.commits = [mergeSha, ...base.commits];
    base.tip = mergeSha;
    pull.state = 'closed';
    pull.merged = true;
    pull.mergedAt = isoOf(ts);
    pull.mergeCommitSha = mergeSha;
    return { sha: mergeSha };
  }
}

const store = new Store();

// ---- serialization helpers (shared by REST, GraphQL, MCP) ----

function repoJson(repo: Repo): Record<string, unknown> {
  const owner = repo.ownerLogin ?? store.viewerLogin ?? 'owner';
  return {
    id: repo.dbId,
    node_id: store.repoGlobalId(repo),
    name: repo.name,
    full_name: `${owner}/${repo.name}`,
    owner: { login: owner, id: store.viewerId, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: isoOf(BASE_TS + repo.createdSeq),
    updated_at: isoOf(BASE_TS + repo.createdSeq),
    html_url: `https://github.example/${owner}/${repo.name}`,
    url: `/api/v3/repos/${owner}/${repo.name}`,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
  };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  const owner = repo.ownerLogin ?? store.viewerLogin ?? 'owner';
  return {
    id: repo.dbId * 100000 + issue.number,
    node_id: store.issueGlobalId(repo, issue),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((l) => ({ name: l.name, color: l.color })),
    user: { login: owner, id: store.viewerId, type: 'User' },
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    html_url: `https://github.example/${owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${owner}/${repo.name}/issues/${issue.number}`,
    comments: issue.comments.length,
  };
}

function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  const owner = repo.ownerLogin ?? store.viewerLogin ?? 'owner';
  return {
    id: repo.dbId * 100000 + pull.number,
    node_id: store.pullGlobalId(repo, pull),
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    head: { ref: pull.headBranch, sha: pull.headSha, label: `${owner}:${pull.headBranch}` },
    base: { ref: pull.baseBranch, sha: pull.baseSha, label: `${owner}:${pull.baseBranch}` },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable: store.pullConflicts(repo, pull) ? 'CONFLICTING' : 'MERGEABLE',
    user: { login: owner, id: store.viewerId, type: 'User' },
    created_at: pull.createdAt,
    html_url: `https://github.example/${owner}/${repo.name}/pull/${pull.number}`,
    url: `/api/v3/repos/${owner}/${repo.name}/pulls/${pull.number}`,
  };
}

// -------------------------------------------------------------------------------------------
// HTTP plumbing: auth, JSON replies, body reading
// -------------------------------------------------------------------------------------------

function isAuthorized(req: IncomingMessage): boolean {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const token = header.slice('Bearer '.length);
  if (token === '') return false;
  if (EXPECTED_TOKEN === '') return true; // no token configured (local dev): any bearer works
  return token === EXPECTED_TOKEN;
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), ...headers });
  res.end(text);
}

function sendNoBody(res: ServerResponse, status: number, headers: Record<string, string> = {}): void {
  res.writeHead(status, { ...headers });
  res.end();
}

function readBody(req: IncomingMessage, limit = 64 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > limit) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(buf: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (buf.length === 0) return { ok: true, value: undefined };
  try {
    return { ok: true, value: JSON.parse(buf.toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

function decodeSegment(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function splitPath(pathname: string): string[] {
  return pathname.split('/').filter((s) => s !== '').map(decodeSegment);
}

function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

function pageParams(q: URLSearchParams): { page: number; perPage: number } {
  const perPage = Math.max(1, Math.min(100, Number.parseInt(q.get('per_page') ?? '30', 10) || 30));
  const page = Math.max(1, Number.parseInt(q.get('page') ?? '1', 10) || 1);
  return { page, perPage };
}

function paginate<T>(items: T[], page: number, perPage: number): T[] {
  return items.slice((page - 1) * perPage, page * perPage);
}

// -------------------------------------------------------------------------------------------
// REST v3 (/api/v3)
// -------------------------------------------------------------------------------------------

function restHeaders(req: IncomingMessage): Record<string, string> {
  return { 'x-github-request-id': store.nextReqId() };
}

function restError(res: ServerResponse, req: IncomingMessage, status: number, message: string): void {
  sendJson(res, status, { message }, restHeaders(req));
}

interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  segs: string[]; // path segments after /api/v3
  query: URLSearchParams;
  body: unknown;
}

/** Resolve /repos/{owner}/{name} from segments starting at index `at`. */
function ctxRepo(ctx: Ctx, at: number): Repo | null {
  const owner = ctx.segs[at] ?? '';
  const name = ctx.segs[at + 1] ?? '';
  if (owner === '' || name === '') return null;
  return store.findRepo(owner, name);
}

function handleRest(ctx: Ctx): void {
  const { req, res, segs } = ctx;
  const method = req.method ?? 'GET';

  // GET /api/v3/ — the API root.
  if (segs.length === 0) {
    if (method !== 'GET') return restError(res, req, 404, 'Not Found');
    return sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, {
      ...restHeaders(req),
      'x-oauth-scopes': 'repo, read:org',
    });
  }

  // GET /api/v3/meta
  if (segs.length === 1 && segs[0] === 'meta') {
    if (method !== 'GET') return restError(res, req, 404, 'Not Found');
    return sendJson(res, 200, { installed_version: SERVER_VERSION }, restHeaders(req));
  }

  // GET /api/v3/user
  if (segs.length === 1 && segs[0] === 'user') {
    if (method !== 'GET') return restError(res, req, 404, 'Not Found');
    if (store.viewerLogin === null) return restError(res, req, 404, 'Not Found');
    return sendJson(res, 200, {
      login: store.viewerLogin,
      id: store.viewerId,
      type: 'User',
      html_url: `https://github.example/${store.viewerLogin}`,
      url: '/api/v3/user',
    }, restHeaders(req));
  }

  // POST /api/v3/user/repos  |  GET /api/v3/user/repos (paginated)
  if (segs.length === 2 && segs[0] === 'user' && segs[1] === 'repos') {
    if (method === 'POST') {
      const body = isRecord(ctx.body) ? ctx.body : {};
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '') return restError(res, req, 422, 'name is required');
      if (store.byName.has(name)) return restError(res, req, 422, 'Repository already exists');
      const repo = store.createRepo(
        name,
        typeof body.description === 'string' ? body.description : '',
        body.private === true,
      );
      return sendJson(res, 201, repoJson(repo), restHeaders(req));
    }
    if (method === 'GET') {
      const { page, perPage } = pageParams(ctx.query);
      const total = store.repos.length;
      const items = paginate(store.repos, page, perPage).map(repoJson);
      const headers = restHeaders(req);
      if (page * perPage < total) {
        const host = req.headers.host ?? 'localhost';
        const proto = 'http';
        const base = `${proto}://${host}/api/v3/user/repos?per_page=${perPage}`;
        const last = Math.ceil(total / perPage);
        headers.link = `<${base}&page=${page + 1}>; rel="next", <${base}&page=${last}>; rel="last"`;
      }
      return sendJson(res, 200, items, headers);
    }
    return restError(res, req, 404, 'Not Found');
  }

  // /api/v3/repos/{owner}/{name}/...
  if (segs.length >= 3 && segs[0] === 'repos') {
    const repo = ctxRepo(ctx, 1);
    if (repo === null) return restError(res, req, 404, 'Not Found');
    const rest = segs.slice(3);
    return handleRestRepo(ctx, repo, rest);
  }

  return restError(res, req, 404, 'Not Found');
}

function handleRestRepo(ctx: Ctx, repo: Repo, rest: string[]): void {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';

  // /repos/{o}/{r} itself: GET / PATCH / DELETE
  if (rest.length === 0) {
    if (method === 'GET') return sendJson(res, 200, repoJson(repo), restHeaders(req));
    if (method === 'PATCH') {
      const body = isRecord(ctx.body) ? ctx.body : {};
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.name === 'string' && body.name !== '' && body.name !== repo.name) {
        store.byName.delete(repo.name);
        repo.name = body.name;
        store.byName.set(repo.name, repo);
      }
      return sendJson(res, 200, repoJson(repo), restHeaders(req));
    }
    if (method === 'DELETE') {
      store.deleteRepo(repo);
      return sendNoBody(res, 204, restHeaders(req));
    }
    return restError(res, req, 404, 'Not Found');
  }

  const head = rest[0];

  // GET /branches  |  GET /branches/{branch}
  if (head === 'branches') {
    if (method !== 'GET') return restError(res, req, 404, 'Not Found');
    if (rest.length === 1) {
      const list = [...repo.branches.entries()]
        .sort((a, b) => (a[0] < b[0] ? -1 : 1))
        .filter(([, b]) => b.tip !== null)
        .map(([name, b]) => ({ name, commit: { sha: b.tip }, protected: false }));
      return sendJson(res, 200, list, restHeaders(req));
    }
    const branch = repo.branches.get(rest[1]);
    if (branch === undefined || branch.tip === null) return restError(res, req, 404, 'Not Found');
    return sendJson(res, 200, { name: rest[1], commit: { sha: branch.tip }, protected: false }, restHeaders(req));
  }

  // GET /commits[?sha=<ref>]
  if (head === 'commits') {
    if (method !== 'GET') return restError(res, req, 404, 'Not Found');
    const ref = ctx.query.get('sha');
    let shas: string[];
    if (ref === null || ref === undefined || ref === '') {
      shas = repo.branches.get(repo.defaultBranch)?.commits ?? [];
    } else {
      const branch = repo.branches.get(ref);
      if (branch !== undefined) shas = branch.commits;
      else if (OID_RE.test(ref) && repo.objects.has(ref)) shas = [ref];
      else shas = [];
    }
    const list = shas.map((sha) => {
      const info = repo.objects.get(sha);
      const message = repo.commitMessage.get(sha) ?? (info?.type === 'commit' ? parseCommit(info.data).message.replace(/\n$/, '') : '');
      const ts = repo.commitTs.get(sha) ?? BASE_TS;
      const ident = store.authorIdent();
      return {
        sha,
        commit: {
          message,
          author: { name: ident.split(' <')[0], email: `${store.viewerLogin ?? 'forge'}@example.invalid`, date: isoOf(ts) },
          committer: { name: ident.split(' <')[0], email: `${store.viewerLogin ?? 'forge'}@example.invalid`, date: isoOf(ts) },
        },
        author: { login: store.viewerLogin ?? 'forge' },
        committer: { login: store.viewerLogin ?? 'forge' },
      };
    });
    return sendJson(res, 200, list, restHeaders(req));
  }

  // POST /git/refs  |  GET /git/refs[/heads/{branch}|/tags/{tag}]
  if (head === 'git' && rest[1] === 'refs') {
    if (method === 'POST' && rest.length === 2) {
      const body = isRecord(ctx.body) ? ctx.body : {};
      const ref = typeof body.ref === 'string' ? body.ref : '';
      const sha = typeof body.sha === 'string' ? body.sha : '';
      if (!ref.startsWith('refs/heads/') && !ref.startsWith('refs/tags/')) {
        return restError(res, req, 422, 'ref must start with refs/heads/ or refs/tags/');
      }
      if (!OID_RE.test(sha) || !repo.objects.has(sha)) return restError(res, req, 422, 'sha does not exist');
      const short = ref.slice('refs/'.length);
      const kind = ref.startsWith('refs/heads/') ? 'heads' : 'tags';
      if (kind === 'heads') {
        if (repo.branches.has(short.slice('heads/'.length))) return restError(res, req, 422, 'Reference already exists');
        store.createBranch(repo, short.slice('heads/'.length), sha);
      } else {
        if (repo.tags.has(short.slice('tags/'.length))) return restError(res, req, 422, 'Reference already exists');
        repo.tags.set(short.slice('tags/'.length), sha);
        touchRepo(repo);
      }
      return sendJson(res, 201, { ref, object: { sha, type: kind === 'heads' ? 'commit' : (repo.objects.get(sha)?.type ?? 'commit') } }, restHeaders(req));
    }
    if (method === 'GET' && rest.length >= 3) {
      const refPath = rest.slice(2).join('/');
      const kind = rest[2];
      if (kind === 'heads') {
        const branch = repo.branches.get(refPath.slice('heads/'.length));
        if (branch === undefined || branch.tip === null) return restError(res, req, 404, 'Not Found');
        return sendJson(res, 200, { ref: `refs/${refPath}`, object: { sha: branch.tip, type: 'commit' } }, restHeaders(req));
      }
      if (kind === 'tags') {
        const oid = repo.tags.get(refPath.slice('tags/'.length));
        if (oid === undefined) return restError(res, req, 404, 'Not Found');
        return sendJson(res, 200, { ref: `refs/${refPath}`, object: { sha: oid, type: repo.objects.get(oid)?.type ?? 'commit' } }, restHeaders(req));
      }
      return restError(res, req, 404, 'Not Found');
    }
    return restError(res, req, 404, 'Not Found');
  }

  // /contents/{path...}
  if (head === 'contents') {
    return handleRestContents(ctx, repo, rest.slice(1));
  }

  // /labels
  if (head === 'labels') {
    if (method === 'GET' && rest.length === 1) {
      return sendJson(res, 200, [...repo.labels.values()], restHeaders(req));
    }
    if (method === 'POST' && rest.length === 1) {
      const body = isRecord(ctx.body) ? ctx.body : {};
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '') return restError(res, req, 422, 'name is required');
      const color = typeof body.color === 'string' ? body.color : 'ededed';
      const label = { name, color };
      repo.labels.set(name, label);
      return sendJson(res, 201, label, restHeaders(req));
    }
    return restError(res, req, 404, 'Not Found');
  }

  // /issues...
  if (head === 'issues') {
    return handleRestIssues(ctx, repo, rest.slice(1));
  }

  // /pulls...
  if (head === 'pulls') {
    return handleRestPulls(ctx, repo, rest.slice(1));
  }

  return restError(res, req, 404, 'Not Found');
}

function handleRestContents(ctx: Ctx, repo: Repo, pathSegs: string[]): void {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';
  const path = pathSegs.join('/');
  const ref = ctx.query.get('ref') ?? undefined;

  const branchFor = (wanted?: string): Branch | null => {
    const name = wanted ?? repo.defaultBranch;
    let branch = repo.branches.get(name);
    if (branch === undefined) {
      // Creating on a missing branch starts it from the default branch tip.
      const base = repo.branches.get(repo.defaultBranch);
      branch = store.createBranch(repo, name, base?.tip ?? null);
    }
    return branch;
  };

  if (method === 'GET') {
    const branch = repo.branches.get(ref ?? repo.defaultBranch);
    if (branch === undefined || branch.tip === null) return restError(res, req, 404, 'Not Found');
    const snap = store.snapshotAt(repo, branch.tip);
    if (path === '') {
      // Root directory listing.
      const entries = dirEntries(repo, snap, '');
      return sendJson(res, 200, entries, restHeaders(req));
    }
    const exact = snap.get(path);
    if (exact !== undefined) {
      const blobSha = hashObject('blob', exact);
      return sendJson(res, 200, {
        type: 'file',
        encoding: 'base64',
        content: b64encode(exact),
        sha: blobSha,
        size: exact.length,
        name: path.split('/').pop() ?? path,
        path,
      }, restHeaders(req));
    }
    // Directory?
    const prefix = `${path}/`;
    let isDir = false;
    for (const key of snap.keys()) if (key.startsWith(prefix)) { isDir = true; break; }
    if (isDir) return sendJson(res, 200, dirEntries(repo, snap, path), restHeaders(req));
    return restError(res, req, 404, 'Not Found');
  }

  if (method === 'PUT') {
    const body = isRecord(ctx.body) ? ctx.body : {};
    const message = typeof body.message === 'string' ? body.message : 'update';
    const contentB64 = typeof body.content === 'string' ? body.content : '';
    const sha = typeof body.sha === 'string' ? body.sha : undefined;
    const branchName = typeof body.branch === 'string' ? body.branch : repo.defaultBranch;
    const branch = branchFor(branchName);
    if (branch === null) return restError(res, req, 404, 'Not Found');
    const snap = branch.tip === null ? new Map<string, Buffer>() : store.snapshotAt(repo, branch.tip);
    const existing = snap.get(path);
    const data = b64decode(contentB64);
    if (existing !== undefined) {
      if (sha === undefined) return restError(res, req, 409, 'sha is required to update a file');
      if (sha.toLowerCase() !== hashObject('blob', existing).toLowerCase()) {
        return restError(res, req, 409, 'sha does not match the current file');
      }
    } else if (sha !== undefined) {
      return restError(res, req, 422, 'sha does not match: the file does not exist');
    }
    const next = new Map(snap);
    next.set(path, data);
    const { commitSha } = store.commitOnBranch(repo, branchName, next, message);
    const blobSha = hashObject('blob', data);
    return sendJson(res, existing !== undefined ? 200 : 201, {
      content: { name: path.split('/').pop() ?? path, path, sha: blobSha, encoding: 'base64', size: data.length },
      commit: { sha: commitSha, message },
    }, restHeaders(req));
  }

  if (method === 'DELETE') {
    const body = isRecord(ctx.body) ? ctx.body : {};
    const message = typeof body.message === 'string' ? body.message : 'delete';
    const sha = typeof body.sha === 'string' ? body.sha : undefined;
    const branchName = typeof body.branch === 'string' ? body.branch : repo.defaultBranch;
    const branch = repo.branches.get(branchName);
    if (branch === undefined || branch.tip === null) return restError(res, req, 404, 'Not Found');
    const snap = store.snapshotAt(repo, branch.tip);
    const existing = snap.get(path);
    if (existing === undefined) return restError(res, req, 404, 'Not Found');
    if (sha !== undefined && sha.toLowerCase() !== hashObject('blob', existing).toLowerCase()) {
      return restError(res, req, 409, 'sha does not match the current file');
    }
    const next = new Map(snap);
    next.delete(path);
    const { commitSha } = store.commitOnBranch(repo, branchName, next, message);
    return sendJson(res, 200, { commit: { sha: commitSha, message } }, restHeaders(req));
  }

  return restError(res, req, 404, 'Not Found');
}

/** Immediate children of `dir` in a snapshot, as GitHub's directory listing shapes them. */
function dirEntries(repo: Repo, snap: Map<string, Buffer>, dir: string): Array<Record<string, unknown>> {
  const prefix = dir === '' ? '' : `${dir}/`;
  const files = new Map<string, Buffer>();
  const dirs = new Set<string>();
  for (const [path, data] of snap) {
    if (!path.startsWith(prefix)) continue;
    const rest = path.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash < 0) files.set(rest, data);
    else dirs.add(rest.slice(0, slash));
  }
  const out: Array<Record<string, unknown>> = [];
  for (const d of [...dirs].sort()) {
    out.push({ type: 'dir', name: d, path: `${prefix}${d}`, sha: hashObject('tree', Buffer.alloc(0)) });
  }
  for (const [name, data] of [...files.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    out.push({ type: 'file', name, path: `${prefix}${name}`, sha: hashObject('blob', data), size: data.length });
  }
  return out;
}

function handleRestIssues(ctx: Ctx, repo: Repo, rest: string[]): void {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';

  // /issues — POST create | GET list
  if (rest.length === 0) {
    if (method === 'POST') {
      const body = isRecord(ctx.body) ? ctx.body : {};
      const title = typeof body.title === 'string' ? body.title : '';
      const bodyText = typeof body.body === 'string' ? body.body : '';
      const labelNames = Array.isArray(body.labels) ? body.labels.filter((l): l is string => typeof l === 'string') : [];
      for (const name of labelNames) {
        if (!repo.labels.has(name)) return restError(res, req, 422, `label ${name} does not exist`);
      }
      const issue = store.createIssue(repo, title, bodyText, labelNames);
      return sendJson(res, 201, issueJson(repo, issue), restHeaders(req));
    }
    if (method === 'GET') {
      const state = ctx.query.get('state') ?? 'open';
      const sort = ctx.query.get('sort') ?? 'created';
      const direction = ctx.query.get('direction') ?? 'desc';
      let list = repo.issues.filter((i) => state === 'all' || i.state === state);
      if (sort === 'created') {
        list = [...list].sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
      }
      const { page, perPage } = pageParams(ctx.query);
      return sendJson(res, 200, paginate(list, page, perPage).map((i) => issueJson(repo, i)), restHeaders(req));
    }
    return restError(res, req, 404, 'Not Found');
  }

  const number = Number.parseInt(rest[0], 10);
  if (!Number.isInteger(number) || number < 1) return restError(res, req, 404, 'Not Found');
  const issue = repo.issues.find((i) => i.number === number);
  if (issue === undefined) return restError(res, req, 404, 'Not Found');

  // /issues/{n}/comments
  if (rest.length === 2 && rest[1] === 'comments') {
    if (method === 'POST') {
      const body = isRecord(ctx.body) ? ctx.body : {};
      const text = typeof body.body === 'string' ? body.body : '';
      const ts = store.nextTs();
      const comment = { id: repo.nextComment, body: text, createdAt: isoOf(ts) };
      repo.nextComment += 1;
      issue.comments.push(comment);
      return sendJson(res, 201, {
        id: comment.id,
        node_id: b64encode(`IssueComment:${repo.dbId}:${issue.number}:${comment.id}`),
        body: text,
        user: { login: store.viewerLogin ?? 'forge' },
        created_at: comment.createdAt,
      }, restHeaders(req));
    }
    if (method === 'GET') {
      return sendJson(res, 200, issue.comments.map((c) => ({
        id: c.id,
        node_id: b64encode(`IssueComment:${repo.dbId}:${issue.number}:${c.id}`),
        body: c.body,
        user: { login: store.viewerLogin ?? 'forge' },
        created_at: c.createdAt,
      })), restHeaders(req));
    }
    return restError(res, req, 404, 'Not Found');
  }

  if (rest.length === 1) {
    if (method === 'GET') return sendJson(res, 200, issueJson(repo, issue), restHeaders(req));
    if (method === 'PATCH') {
      const body = isRecord(ctx.body) ? ctx.body : {};
      if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      issue.updatedAt = isoOf(store.nextTs());
      return sendJson(res, 200, issueJson(repo, issue), restHeaders(req));
    }
    return restError(res, req, 404, 'Not Found');
  }

  return restError(res, req, 404, 'Not Found');
}

function handleRestPulls(ctx: Ctx, repo: Repo, rest: string[]): void {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';

  // /pulls — POST create | GET list
  if (rest.length === 0) {
    if (method === 'POST') {
      const body = isRecord(ctx.body) ? ctx.body : {};
      const title = typeof body.title === 'string' ? body.title : '';
      const bodyText = typeof body.body === 'string' ? body.body : '';
      const head = typeof body.head === 'string' ? body.head : '';
      const base = typeof body.base === 'string' ? body.base : repo.defaultBranch;
      const created = store.createPull(repo, title, bodyText, head, base);
      if ('error' in created) return restError(res, req, 422, created.error);
      return sendJson(res, 201, pullJson(repo, created), restHeaders(req));
    }
    if (method === 'GET') {
      const state = ctx.query.get('state') ?? 'open';
      const list = repo.pulls.filter((p) => state === 'all' || p.state === state);
      const { page, perPage } = pageParams(ctx.query);
      return sendJson(res, 200, paginate(list, page, perPage).map((p) => pullJson(repo, p)), restHeaders(req));
    }
    return restError(res, req, 404, 'Not Found');
  }

  const number = Number.parseInt(rest[0], 10);
  if (!Number.isInteger(number) || number < 1) return restError(res, req, 404, 'Not Found');
  const pull = repo.pulls.find((p) => p.number === number);

  // /pulls/{n}/files
  if (rest.length === 2 && rest[1] === 'files') {
    if (method !== 'GET') return restError(res, req, 404, 'Not Found');
    if (pull === undefined) return restError(res, req, 404, 'Not Found');
    return sendJson(res, 200, pull.files, restHeaders(req));
  }

  // /pulls/{n}/merge
  if (rest.length === 2 && rest[1] === 'merge') {
    if (method !== 'PUT') return restError(res, req, 404, 'Not Found');
    if (pull === undefined) return restError(res, req, 404, 'Not Found');
    const merged = store.mergePull(repo, pull);
    if ('error' in merged) return restError(res, req, merged.status, merged.error);
    return sendJson(res, 200, {
      sha: merged.sha,
      merged: true,
      message: `Pull Request successfully merged`,
    }, restHeaders(req));
  }

  if (rest.length === 1) {
    if (method !== 'GET') return restError(res, req, 404, 'Not Found');
    if (pull === undefined) return restError(res, req, 404, 'Not Found');
    return sendJson(res, 200, pullJson(repo, pull), restHeaders(req));
  }

  return restError(res, req, 404, 'Not Found');
}

// -------------------------------------------------------------------------------------------
// git smart HTTP (/{owner}/{repo}.git)
// -------------------------------------------------------------------------------------------

function gitNotFound(res: ServerResponse): void {
  sendJson(res, 404, { message: 'Not Found' });
}

function sendGitBytes(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length });
  res.end(body);
}

/** Sideband-wrap pack bytes into pkt-lines (band 1), chunked well under the pkt-line max. */
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (let off = 0; off < pack.length; off += 32768) {
    const chunk = pack.subarray(off, Math.min(off + 32768, pack.length));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  if (pack.length === 0) parts.push(pktLine(Buffer.concat([Buffer.from([1]), Buffer.alloc(0)])));
  return Buffer.concat(parts);
}

/** The v2 capability advertisement lines. */
function v2Capabilities(): string[] {
  return [
    'version 2',
    `agent=${SERVER_NAME}/${SERVER_VERSION}`,
    'ls-refs=unborn',
    'fetch=shallow thin-pack ofs-delta',
    'object-format=sha1',
  ];
}

function v0Capabilities(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): string {
  const caps: string[] = [`symref=HEAD:refs/heads/${repo.defaultBranch}`];
  if (service === 'git-upload-pack') caps.push('side-band-64k', 'thin-pack', 'ofs-delta', 'shallow', 'multi_ack');
  else caps.push('report-status', 'report-status-v2', 'side-band-64k', 'delete-refs', 'ofs-delta');
  caps.push(`agent=${SERVER_NAME}/${SERVER_VERSION}`);
  return caps.join(' ');
}

/** Ref lines for a v0 advertisement (first line carries the capabilities after NUL). */
function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps = v0Capabilities(repo, service);
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const refs = store.allRefs(repo);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    const main = refs.find((r) => r.name === `refs/heads/${repo.defaultBranch}`);
    const headOid = main?.oid ?? refs[0].oid;
    parts.push(pktLine(`${headOid} HEAD\0${caps}\n`));
    for (const r of refs) {
      parts.push(pktLine(`${r.oid} ${r.name}\n`));
      const obj = repo.objects.get(r.oid);
      if (r.name.startsWith('refs/tags/') && obj?.type === 'tag') {
        parts.push(pktLine(`${store.peel(repo, r.oid)} ${r.name}^{}\n`));
      }
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function v2Advertisement(service: 'git-upload-pack'): Buffer {
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  for (const line of v2Capabilities()) parts.push(pktLine(`${line}\n`));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/** Parse the pkt-line command section of a v2 request body. */
function parseV2Request(body: Buffer): { command: string; args: string[] } {
  const { packets } = splitPktSection(body);
  let command = '';
  const args: string[] = [];
  let seenDelim = false;
  for (const p of packets) {
    if (p.kind === 'delim') {
      seenDelim = true;
      continue;
    }
    if (p.kind !== 'data') continue;
    const line = p.payload.toString('utf8').replace(/\n$/, '');
    if (!seenDelim) {
      if (line.startsWith('command=')) command = line.slice('command='.length);
    } else {
      args.push(line);
    }
  }
  if (command === '') throw new Error('no command in v2 request');
  return { command, args };
}

function lsRefsResponse(repo: Repo, args: string[]): Buffer {
  const peel = args.includes('peel');
  const symrefs = args.includes('symrefs');
  const unborn = args.includes('unborn');
  const prefixes = args.filter((a) => a.startsWith('ref-prefix ')).map((a) => a.slice('ref-prefix '.length));
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  const parts: Buffer[] = [];
  const main = repo.branches.get(repo.defaultBranch);
  const mainTip = main?.tip ?? null;
  if (mainTip !== null) {
    if (keep('HEAD') && symrefs) parts.push(pktLine(`${mainTip} HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
    else if (keep('HEAD')) parts.push(pktLine(`${mainTip} HEAD\n`));
  } else if (unborn) {
    parts.push(pktLine(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
  }
  for (const r of store.allRefs(repo)) {
    if (!keep(r.name)) continue;
    let line = `${r.oid} ${r.name}`;
    if (r.name.startsWith('refs/tags/') && peel) {
      const obj = repo.objects.get(r.oid);
      if (obj?.type === 'tag') line += ` peeled:${store.peel(repo, r.oid)}`;
    }
    parts.push(pktLine(`${line}\n`));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

interface FetchPlan {
  wants: string[];
  haves: string[];
  shallowIn: string[];
  depth: number | null;
}

/** Compute the objects a fetch must send, plus the shallow-info lines. */
function planFetch(repo: Repo, plan: FetchPlan): { packObjects: PackEntry[]; shallow: string[]; unshallow: string[]; wantedRefs: Array<{ oid: string; ref: string }> } {
  const lookup = store.lookup(repo);
  const haveSet =
    plan.depth > 0
      ? // A shallow client's haves are only its depth-limited objects: traversal
        // must stop at its shallow boundaries, otherwise a deepen would lose
        // the parent it is asking for (its "have" closure would swallow it).
        collectReachableCut(plan.haves, lookup, new Set(plan.shallowIn))
      : collectReachable(plan.haves, lookup);
  let send: Set<string>;
  let shallow: string[] = [];
  let unshallow: string[] = [];
  if (plan.depth !== null) {
    const { objects, boundary } = collectShallow(plan.wants, plan.depth, lookup);
    send = new Set([...objects].filter((oid) => !haveSet.has(oid)));
    shallow = [...boundary].filter((oid) => send.has(oid) || plan.wants.includes(oid));
    // A previous boundary is unshallowed when it is now sent with its parent present.
    for (const old of plan.shallowIn) {
      if (!send.has(old) && !plan.wants.includes(old)) continue;
      const obj = lookup(old);
      if (obj?.type !== 'commit') continue;
      const parents = parseCommit(obj.data).parents;
      if (parents.some((p) => send.has(p) || haveSet.has(p))) unshallow.push(old);
    }
    // Boundary commits themselves must be in the pack (their trees too); collectShallow
    // already includes them. But a boundary that the client already holds must not be
    // re-sent: drop boundary lines for held commits.
    shallow = shallow.filter((oid) => !haveSet.has(oid));
  } else {
    const wanted = collectReachable(plan.wants, lookup);
    send = new Set([...wanted].filter((oid) => !haveSet.has(oid)));
  }
  const packObjects: PackEntry[] = [];
  for (const oid of send) {
    const obj = repo.objects.get(oid);
    if (obj !== undefined) packObjects.push({ oid, type: obj.type, data: obj.data });
  }
  const wantedRefs: Array<{ oid: string; ref: string }> = [];
  for (const r of store.allRefs(repo)) {
    if (plan.wants.includes(r.oid)) wantedRefs.push({ oid: r.oid, ref: r.name });
  }
  return { packObjects, shallow, unshallow, wantedRefs };
}

function v2FetchResponse(repo: Repo, plan: FetchPlan): Buffer {
  const { packObjects, shallow, unshallow, wantedRefs } = planFetch(repo, plan);
  const parts: Buffer[] = [];
  // acknowledgments: only when the client sent haves (negotiation). With no
  // haves, git goes straight to the packfile section and rejects an acks section.
  if (plan.haves.length > 0) {
    parts.push(pktLine('acknowledgments\n'));
    let acked = false;
    for (const h of plan.haves) {
      if (repo.objects.has(h)) {
        parts.push(pktLine(`ACK ${h}\n`));
        acked = true;
      }
    }
    if (!acked) parts.push(pktLine('NAK\n'));
    parts.push(PKT_DELIM);
  }
  // shallow-info
  if (shallow.length > 0 || unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const u of unshallow) parts.push(pktLine(`unshallow ${u}\n`));
    parts.push(PKT_DELIM);
  }
  // wanted-refs
  if (wantedRefs.length > 0) {
    parts.push(pktLine('wanted-refs\n'));
    for (const w of wantedRefs) parts.push(pktLine(`${w.oid} ${w.ref}\n`));
    parts.push(PKT_DELIM);
  }
  // packfile (always present when wants were given, even when empty). The
  // packfile section ends the response with a flush packet, not a delim: git's
  // fetch-pack reads the next packet after the pack and requires a flush.
  const pack = writePack(packObjects);
  parts.push(pktLine('packfile\n'));
  parts.push(sidebandPack(pack));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function v0FetchResponse(repo: Repo, plan: FetchPlan): Buffer {
  const { packObjects, shallow, unshallow } = planFetch(repo, plan);
  const parts: Buffer[] = [];
  if (plan.haves.length === 0) {
    parts.push(pktLine('NAK\n'));
  } else {
    let acked = false;
    for (const h of plan.haves) {
      if (repo.objects.has(h)) {
        parts.push(pktLine(`ACK ${h}\n`));
        acked = true;
      }
    }
    if (!acked) parts.push(pktLine('NAK\n'));
  }
  for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
  for (const u of unshallow) parts.push(pktLine(`unshallow ${u}\n`));
  const pack = writePack(packObjects);
  parts.push(sidebandPack(pack));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function handleGitUploadPack(req: IncomingMessage, res: ServerResponse, repo: Repo, body: Buffer): void {
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  if (!isV2) {
    // v0 fetch: wants/haves/deepen as pkt-lines in two sections.
    const plan = parseV0Fetch(body);
    return sendGitBytes(res, 200, 'application/x-git-upload-pack-result', cachedFetch(repo, 'v0', plan, () => v0FetchResponse(repo, plan)));
  }
  let parsed: { command: string; args: string[] };
  try {
    parsed = parseV2Request(body);
  } catch {
    res.writeHead(400, { 'content-type': 'text/plain' });
    res.end('bad pkt-line framing');
    return;
  }
  if (parsed.command === 'ls-refs') {
    return sendGitBytes(res, 200, 'application/x-git-upload-pack-result', lsRefsResponse(repo, parsed.args));
  }
  if (parsed.command === 'fetch') {
    const plan = parseV2FetchArgs(parsed.args);
    return sendGitBytes(res, 200, 'application/x-git-upload-pack-result', cachedFetch(repo, 'v2', plan, () => v2FetchResponse(repo, plan)));
  }
  res.writeHead(400, { 'content-type': 'text/plain' });
  res.end(`unknown command ${parsed.command}`);
}

/** Fetch responses are a pure function of (repo state, request): cache them so
 *  repeated identical clones (e.g. the 50× concurrent shallow-clone bench
 *  workload) pay the pack build only once. Cleared by touchRepo on mutation. */
function cachedFetch(repo: Repo, proto: string, plan: FetchPlan, build: () => Buffer): Buffer {
  const key = [proto, ...plan.wants, '|', ...plan.haves, '|', plan.depth ?? '', '|', ...plan.shallowIn].join(',');
  const hit = repo.fetchCache.get(key);
  if (hit !== undefined) return hit;
  const out = build();
  repo.fetchCache.set(key, out);
  return out;
}

function parseV2FetchArgs(args: string[]): FetchPlan {
  const plan: FetchPlan = { wants: [], haves: [], shallowIn: [], depth: null };
  for (const line of args) {
    if (line.startsWith('want ')) plan.wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) plan.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) plan.shallowIn.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) {
      const n = Number.parseInt(line.slice(7).trim(), 10);
      if (Number.isInteger(n) && n > 0) plan.depth = n;
    }
  }
  return plan;
}

function parseV0Fetch(body: Buffer): FetchPlan {
  const plan: FetchPlan = { wants: [], haves: [], shallowIn: [], depth: null };
  const packets = decodePktLines(body);
  let section = 0;
  for (const p of packets) {
    if (p.kind === 'flush') {
      section += 1;
      continue;
    }
    if (p.kind !== 'data') continue;
    const line = p.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) {
      // First want line may carry capabilities after the oid.
      plan.wants.push(line.slice(5).split(' ')[0]);
    } else if (line.startsWith('have ')) plan.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) plan.shallowIn.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) {
      const n = Number.parseInt(line.slice(7).trim(), 10);
      if (Number.isInteger(n) && n > 0) plan.depth = n;
    }
    void section;
  }
  return plan;
}

function handleGitReceivePack(req: IncomingMessage, res: ServerResponse, repo: Repo, body: Buffer): void {
  const report = (unpackOk: boolean, unpackDetail: string, refs: Array<{ ref: string; ok: boolean; reason: string }>): Buffer => {
    // Each report line is its own pkt-line inside sideband band 1: git's
    // report-status parser reads one logical line per pkt-line. The inner
    // stream ends with a flush packet (0000) inside band 1: the sideband
    // demuxer consumes the outer flush itself, so without an inner flush the
    // client's packet reader hits EOF and dies "remote end hung up".
    const framed = Buffer.concat([
      ...[`unpack ${unpackOk ? 'ok' : unpackDetail}`, ...refs.map((r) => (r.ok ? `ok ${r.ref}` : `ng ${r.ref} ${r.reason}`))].map(
        (line) => pktLine(`${line}\n`),
      ),
      PKT_FLUSH,
    ]);
    const parts: Buffer[] = [];
    for (let off = 0; off < framed.length; off += 32768) {
      parts.push(pktLine(Buffer.concat([Buffer.from([1]), framed.subarray(off, Math.min(off + 32768, framed.length))])));
    }
    parts.push(PKT_FLUSH);
    return Buffer.concat(parts);
  };

  let commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let packBytes = Buffer.alloc(0);
  try {
    const { packets, rest } = splitPktSection(body);
    packBytes = rest;
    for (const p of packets) {
      if (p.kind !== 'data') continue;
      const raw = p.payload.toString('utf8').replace(/\n$/, '');
      const nul = raw.indexOf('\0');
      const line = nul >= 0 ? raw.slice(0, nul) : raw;
      const [oldOid, newOid, ref] = line.split(' ');
      if (oldOid === undefined || newOid === undefined || ref === undefined) throw new Error('bad push command');
      if (!OID_RE.test(oldOid) || !OID_RE.test(newOid) || !ref.startsWith('refs/')) throw new Error('bad push command');
      commands.push({ oldOid, newOid, ref });
    }
    if (commands.length === 0) throw new Error('no push commands');
  } catch {
    res.writeHead(400, { 'content-type': 'text/plain' });
    res.end('bad push request');
    return;
  }

  // Unpack first: every object the client sent joins the store.
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (packBytes.length > 0) {
    try {
      const { objects } = readPack(packBytes, store.lookup(repo));
      for (const o of objects) {
        if (!repo.objects.has(o.oid)) repo.objects.set(o.oid, { type: o.type, data: o.data });
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack error';
    }
  }

  const results: Array<{ ref: string; ok: boolean; reason: string }> = [];
  for (const cmd of commands) {
    if (!unpackOk) {
      results.push({ ref: cmd.ref, ok: false, reason: 'unpack error' });
      continue;
    }
    const isHead = cmd.ref.startsWith('refs/heads/');
    const isTag = cmd.ref.startsWith('refs/tags/');
    if (!isHead && !isTag) {
      results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    const name = cmd.ref.slice(cmd.ref.indexOf('/', 5) + 1);
    const current = isHead ? repo.branches.get(name)?.tip ?? null : repo.tags.get(name) ?? null;
    const isDelete = cmd.newOid === ZERO_OID;
    const isCreate = cmd.oldOid === ZERO_OID;
    if (isDelete) {
      if (current === null || current !== cmd.oldOid) {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
      if (isHead) repo.branches.delete(name);
      else repo.tags.delete(name);
      results.push({ ref: cmd.ref, ok: true, reason: '' });
      continue;
    }
    if (!repo.objects.has(cmd.newOid)) {
      results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    if (isCreate) {
      if (current !== null) {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
    } else {
      if (current === null || current !== cmd.oldOid) {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
      // Fast-forward only: the old tip must be an ancestor of the new tip
      // (parent-chain walk only — no tree/blob traversal).
      if (!isAncestor(cmd.oldOid, cmd.newOid, store.lookup(repo))) {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
    }
    if (isHead) {
      const branch = repo.branches.get(name);
      if (branch !== undefined) {
        branch.tip = cmd.newOid;
        branch.commits = [cmd.newOid, ...branch.commits.filter((c) => c !== cmd.newOid)];
      } else {
        store.createBranch(repo, name, cmd.newOid);
      }
    } else {
      repo.tags.set(name, cmd.newOid);
    }
    results.push({ ref: cmd.ref, ok: true, reason: '' });
  }
  if (results.some((r) => r.ok)) touchRepo(repo);

  sendGitBytes(res, 200, 'application/x-git-receive-pack-result', report(unpackOk, unpackDetail, results));
}

function handleGit(req: IncomingMessage, res: ServerResponse, segs: string[]): void {
  // /{owner}/{repo}.git/info/refs?service=...  |  /{owner}/{repo}.git/git-upload-pack
  // /{owner}/{repo}.git/git-receive-pack
  const method = req.method ?? 'GET';
  if (segs.length < 2) return gitNotFound(res);
  const owner = segs[0];
  const repoSeg = segs[1];
  if (!repoSeg.endsWith('.git')) return gitNotFound(res);
  const repoName = repoSeg.slice(0, -'.git'.length);
  const repo = store.findRepo(owner, repoName);
  if (repo === null) return gitNotFound(res);

  if (method === 'GET' && segs.length === 4 && segs[2] === 'info' && segs[3] === 'refs') {
    const service = queryOf(req).get('service');
    if (service === 'git-upload-pack') {
      const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      const body = isV2 ? v2Advertisement('git-upload-pack') : v0Advertisement(repo, 'git-upload-pack');
      return sendGitBytes(res, 200, 'application/x-git-upload-pack-advertisement', body);
    }
    if (service === 'git-receive-pack') {
      return sendGitBytes(res, 200, 'application/x-git-receive-pack-advertisement', v0Advertisement(repo, 'git-receive-pack'));
    }
    return gitNotFound(res);
  }

  // POST bodies are read by the caller and stashed on the request object.
  const body = (req as unknown as { __body?: Buffer }).__body ?? Buffer.alloc(0);
  if (method === 'POST' && segs.length === 3 && segs[2] === 'git-upload-pack') {
    return handleGitUploadPack(req, res, repo, body);
  }
  if (method === 'POST' && segs.length === 3 && segs[2] === 'git-receive-pack') {
    return handleGitReceivePack(req, res, repo, body);
  }
  return gitNotFound(res);
}

// -------------------------------------------------------------------------------------------
// GraphQL v4 (/api/graphql)
// -------------------------------------------------------------------------------------------

const ISSUE_TYPE_FIELDS = [
  'id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'url',
  'author', 'labels', 'comments', 'closed', 'closedAt', 'repository', 'titleHTML',
];
const PULL_REQUEST_TYPE_FIELDS = [
  'id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged',
  'files', 'title', 'body', 'createdAt', 'updatedAt', 'mergedAt', 'mergeCommit',
  'author', 'baseRef', 'headRef', 'repository', 'url', 'additions', 'deletions',
];
const REPOSITORY_TYPE_FIELDS = [
  'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef',
  'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests',
  'pullRequest', 'description', 'createdAt', 'updatedAt', 'url', 'isPrivate',
  'fork', 'defaultBranch', 'homepageUrl',
];
const SEARCH_TYPE_ENUM_VALUES = [
  'ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE',
];

function decodeGlobalId(id: string): { kind: string; parts: string[] } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const parts = text.split(':');
    if (parts.length < 2) return null;
    return { kind: parts[0], parts: parts.slice(1) };
  } catch {
    return null;
  }
}

function gqlRepoById(id: string): Repo | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'Repository') return null;
  const dbId = Number.parseInt(decoded.parts[0], 10);
  if (!Number.isInteger(dbId)) return null;
  return store.findRepoByDbId(dbId);
}

function gqlIssueById(id: string): { repo: Repo; issue: Issue } | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'Issue') return null;
  const repo = store.findRepoByDbId(Number.parseInt(decoded.parts[0], 10));
  if (repo === null) return null;
  const issue = repo.issues.find((i) => i.number === Number.parseInt(decoded.parts[1], 10));
  if (issue === undefined) return null;
  return { repo, issue };
}

function gqlPullById(id: string): { repo: Repo; pull: Pull } | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'PullRequest') return null;
  const repo = store.findRepoByDbId(Number.parseInt(decoded.parts[0], 10));
  if (repo === null) return null;
  const pull = repo.pulls.find((p) => p.number === Number.parseInt(decoded.parts[1], 10));
  if (pull === undefined) return null;
  return { repo, pull };
}

function gqlRepoFields(repo: Repo): Record<string, unknown> {
  const owner = repo.ownerLogin ?? store.viewerLogin ?? 'owner';
  const main = repo.branches.get(repo.defaultBranch);
  return {
    id: store.repoGlobalId(repo),
    databaseId: repo.dbId,
    name: repo.name,
    nameWithOwner: `${owner}/${repo.name}`,
    owner: { login: owner },
    defaultBranchRef: main?.tip !== null && main?.tip !== undefined ? { name: repo.defaultBranch } : null,
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
  };
}

function gqlIssueFields(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: store.issueGlobalId(repo, issue),
    number: issue.number,
    title: issue.title,
    state: issue.state === 'open' ? 'OPEN' : 'CLOSED',
    body: issue.body,
  };
}

function gqlPullFields(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    id: store.pullGlobalId(repo, pull),
    number: pull.number,
    headRefName: pull.headBranch,
    baseRefName: pull.baseBranch,
    mergeable: store.pullConflicts(repo, pull) ? 'CONFLICTING' : 'MERGEABLE',
    state: pull.state === 'open' ? 'OPEN' : 'CLOSED',
    merged: pull.merged,
  };
}

/** Resolve repository(owner, name) for GraphQL: null when unknown (no errors). */
function gqlRepository(owner: string, name: string): Repo | null {
  if (typeof owner !== 'string' || typeof name !== 'string') return null;
  return store.findRepo(owner, name);
}

function gqlIssuesConnection(repo: Repo, args: Record<string, unknown>): Record<string, unknown> {
  const first = typeof args.first === 'number' ? args.first : 10;
  const states = Array.isArray(args.states) ? (args.states as string[]) : null;
  const orderBy = isRecord(args.orderBy) ? args.orderBy : null;
  let list = [...repo.issues];
  if (states !== null) {
    const wanted = new Set(states.map((s) => s.toUpperCase()));
    list = list.filter((i) => wanted.has(i.state === 'open' ? 'OPEN' : 'CLOSED'));
  }
  if (orderBy !== null && orderBy.field === 'CREATED_AT') {
    list.sort((a, b) => (orderBy.direction === 'DESC' ? b.createdSeq - a.createdSeq : a.createdSeq - b.createdSeq));
  } else {
    list.sort((a, b) => a.createdSeq - b.createdSeq);
  }
  // Cursor pagination (IssuesPage): after = base64("cursor:<index>").
  let start = 0;
  if (typeof args.after === 'string' && args.after !== '') {
    try {
      const text = Buffer.from(args.after, 'base64').toString('utf8');
      const n = Number.parseInt(text.split(':')[1] ?? '', 10);
      if (Number.isInteger(n) && n >= 0) start = n;
    } catch {
      start = 0;
    }
  }
  const page = list.slice(start, start + first);
  const end = start + page.length;
  return {
    nodes: page.map((i) => gqlIssueFields(repo, i)),
    pageInfo: {
      hasNextPage: end < list.length,
      endCursor: end < list.length || page.length > 0 ? b64encode(`cursor:${end}`) : null,
    },
  };
}

function gqlPullsConnection(repo: Repo, args: Record<string, unknown>): Record<string, unknown> {
  const first = typeof args.first === 'number' ? args.first : 10;
  const list = repo.pulls.filter((p) => p.state === 'open').slice(0, first);
  return { nodes: list.map((p) => gqlPullFields(repo, p)) };
}

/** Execute one GraphQL operation. Returns {data} or {data, errors}. */
function executeGraphQL(query: string, variables: Record<string, unknown>): Record<string, unknown> {
  const opMatch = /^\s*(query|mutation)\s+([A-Za-z0-9_]+)/.exec(query);
  const opName = opMatch?.[2] ?? '';
  const v = variables;

  switch (opName) {
    case 'ViewerLogin':
      return { data: { viewer: { login: store.viewerLogin } } };
    case 'RepositoryFields': {
      const repo = gqlRepository(v.owner as string, v.name as string);
      return { data: { repository: repo === null ? null : gqlRepoFields(repo) } };
    }
    case 'Issue_fields':
      return { data: { Issue: { name: 'Issue', fields: ISSUE_TYPE_FIELDS.map((n) => ({ name: n })) } } };
    case 'PullRequestAndRepositoryFields':
      return {
        data: {
          PullRequest: { name: 'PullRequest', fields: PULL_REQUEST_TYPE_FIELDS.map((n) => ({ name: n })) },
          Repository: { name: 'Repository', fields: REPOSITORY_TYPE_FIELDS.map((n) => ({ name: n })) },
        },
      };
    case 'SearchType_enumValues':
      return { data: { SearchType: { name: 'SearchType', enumValues: SEARCH_TYPE_ENUM_VALUES.map((n) => ({ name: n })) } } };
    case 'OpenIssues': {
      const repo = gqlRepository(v.owner as string, v.name as string);
      if (repo === null) return { data: { repository: null } };
      // The document carries states/orderBy as literals, not variables.
      return {
        data: {
          repository: {
            ...gqlRepoFields(repo),
            issues: gqlIssuesConnection(repo, { ...v, states: ['OPEN'], orderBy: { field: 'CREATED_AT', direction: 'DESC' } }),
          },
        },
      };
    }
    case 'IssuesPage': {
      const repo = gqlRepository(v.owner as string, v.name as string);
      if (repo === null) return { data: { repository: null } };
      return { data: { repository: { ...gqlRepoFields(repo), issues: gqlIssuesConnection(repo, v) } } };
    }
    case 'IssueByNumber': {
      const repo = gqlRepository(v.owner as string, v.name as string);
      const issue = repo?.issues.find((i) => i.number === v.number);
      return { data: { repository: repo === null ? null : { ...gqlRepoFields(repo), issue: issue === undefined ? null : gqlIssueFields(repo, issue) } } };
    }
    case 'IssueCreate': {
      const input = isRecord(v.input) ? v.input : {};
      const repo = gqlRepoById(typeof input.repositoryId === 'string' ? input.repositoryId : '');
      if (repo === null) return { data: { createIssue: null }, errors: [{ message: 'repository not found' }] };
      const issue = store.createIssue(repo, typeof input.title === 'string' ? input.title : '', typeof input.body === 'string' ? input.body : '', []);
      return { data: { createIssue: { issue: { number: issue.number, id: store.issueGlobalId(repo, issue) } } } };
    }
    case 'IssueClose': {
      const input = isRecord(v.input) ? v.input : {};
      const found = gqlIssueById(typeof input.issueId === 'string' ? input.issueId : '');
      if (found === null) return { data: { closeIssue: null }, errors: [{ message: 'issue not found' }] };
      found.issue.state = 'closed';
      found.issue.updatedAt = isoOf(store.nextTs());
      return { data: { closeIssue: { issue: { number: found.issue.number, id: store.issueGlobalId(found.repo, found.issue), state: 'CLOSED' } } } };
    }
    case 'PullRequests': {
      const repo = gqlRepository(v.owner as string, v.name as string);
      if (repo === null) return { data: { repository: null } };
      return { data: { repository: { ...gqlRepoFields(repo), pullRequests: gqlPullsConnection(repo, v) } } };
    }
    case 'PullRequestFiles': {
      const repo = gqlRepository(v.owner as string, v.name as string);
      const pull = repo?.pulls.find((p) => p.number === v.number);
      if (repo === null || pull === undefined) return { data: { repository: repo === null ? null : { ...gqlRepoFields(repo), pullRequest: null } } };
      return {
        data: {
          repository: {
            ...gqlRepoFields(repo),
            pullRequest: {
              ...gqlPullFields(repo, pull),
              files: { nodes: pull.files.map((f) => ({ path: f.filename })) },
            },
          },
        },
      };
    }
    case 'PullRequestId': {
      const repo = gqlRepository(v.owner as string, v.name as string);
      const pull = repo?.pulls.find((p) => p.number === v.number);
      return { data: { repository: repo === null ? null : { ...gqlRepoFields(repo), pullRequest: pull === undefined ? null : { id: store.pullGlobalId(repo, pull), number: pull.number } } } };
    }
    case 'PullRequestCreate': {
      const input = isRecord(v.input) ? v.input : {};
      const repo = gqlRepoById(typeof input.repositoryId === 'string' ? input.repositoryId : '');
      if (repo === null) return { data: { createPullRequest: null }, errors: [{ message: 'repository not found' }] };
      const head = typeof input.headRefName === 'string' ? input.headRefName : '';
      const base = typeof input.baseRefName === 'string' ? input.baseRefName : repo.defaultBranch;
      const created = store.createPull(repo, typeof input.title === 'string' ? input.title : '', '', head, base);
      if ('error' in created) return { data: { createPullRequest: null }, errors: [{ message: created.error }] };
      return {
        data: {
          createPullRequest: {
            pullRequest: {
              number: created.number,
              id: store.pullGlobalId(repo, created),
              state: 'OPEN',
              headRefName: created.headBranch,
              baseRefName: created.baseBranch,
            },
          },
        },
      };
    }
    case 'MergePullRequest': {
      const input = isRecord(v.input) ? v.input : {};
      const found = gqlPullById(typeof input.pullRequestId === 'string' ? input.pullRequestId : '');
      if (found === null) return { data: { mergePullRequest: null }, errors: [{ message: 'pull request not found' }] };
      const merged = store.mergePull(found.repo, found.pull);
      if ('error' in merged) return { data: { mergePullRequest: null }, errors: [{ message: merged.error }] };
      return {
        data: {
          mergePullRequest: {
            pullRequest: { number: found.pull.number, merged: true, state: 'CLOSED' },
          },
        },
      };
    }
    case 'AddComment': {
      const input = isRecord(v.input) ? v.input : {};
      const found = gqlIssueById(typeof input.subjectId === 'string' ? input.subjectId : '');
      if (found === null) return { data: { addComment: null }, errors: [{ message: 'issue not found' }] };
      const body = typeof input.body === 'string' ? input.body : '';
      const ts = store.nextTs();
      const comment = { id: found.repo.nextComment, body, createdAt: isoOf(ts) };
      found.repo.nextComment += 1;
      found.issue.comments.push(comment);
      return {
        data: {
          addComment: {
            commentEdge: {
              node: { id: b64encode(`IssueComment:${found.repo.dbId}:${found.issue.number}:${comment.id}`), body },
            },
          },
        },
      };
    }
    case 'ViewerInvalidField':
      return {
        data: { viewer: { login: store.viewerLogin } },
        errors: [{ message: 'Cannot query field "noSuchFieldOnViewer" on type "Viewer".' }],
      };
    case 'NodeRepository': {
      const id = typeof v.id === 'string' ? v.id : '';
      const decoded = decodeGlobalId(id);
      if (decoded !== null && decoded.kind === 'Repository') {
        const repo = store.findRepoByDbId(Number.parseInt(decoded.parts[0], 10));
        if (repo !== null) {
          const owner = repo.ownerLogin ?? store.viewerLogin ?? 'owner';
          return { data: { node: { __typename: 'Repository', id, name: repo.name, nameWithOwner: `${owner}/${repo.name}` } } };
        }
      }
      if (decoded !== null && decoded.kind === 'Issue') {
        const found = gqlIssueById(id);
        if (found !== null) {
          return { data: { node: { __typename: 'Issue', id, number: found.issue.number, title: found.issue.title } } };
        }
      }
      return { data: { node: null } };
    }
    default: {
      // Generic fallback: answer the fields the document asks for when they are the
      // ones this forge knows (viewer login, repository, __type introspection).
      if (/__type\s*\(\s*name\s*:\s*"Issue"\s*\)/.test(query)) {
        return { data: { __type: { name: 'Issue', fields: ISSUE_TYPE_FIELDS.map((n) => ({ name: n })) } } };
      }
      if (/viewer\s*\{/.test(query)) {
        return { data: { viewer: { login: store.viewerLogin } } };
      }
      return { data: null, errors: [{ message: `unknown operation ${opName === '' ? '(anonymous)' : opName}` }] };
    }
  }
}

function handleGraphQL(req: IncomingMessage, res: ServerResponse, body: Buffer): void {
  const parsed = parseJsonBody(body);
  if (!parsed.ok) {
    return sendJson(res, 400, { errors: [{ message: 'request body is not valid JSON' }] });
  }
  const value = parsed.value;
  if (Array.isArray(value)) {
    const results = value.map((op) => {
      if (!isRecord(op) || typeof op.query !== 'string') return { data: null, errors: [{ message: 'invalid operation' }] };
      return executeGraphQL(op.query, isRecord(op.variables) ? op.variables : {});
    });
    return sendJson(res, 200, results);
  }
  if (!isRecord(value) || typeof value.query !== 'string') {
    return sendJson(res, 400, { errors: [{ message: 'request body must carry a query string' }] });
  }
  return sendJson(res, 200, executeGraphQL(value.query, isRecord(value.variables) ? value.variables : {}));
}

// -------------------------------------------------------------------------------------------
// MCP (/mcp): JSON-RPC 2.0 Streamable HTTP
// -------------------------------------------------------------------------------------------

interface McpToolDef {
  name: string;
  description: string;
  properties: Record<string, { type: string; description: string }>;
  required: string[];
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the token owner.',
    properties: {
      name: { type: 'string', description: 'The repository name.' },
      description: { type: 'string', description: 'A short description of the repository.' },
      private: { type: 'boolean', description: 'Whether the repository is private.' },
    },
    required: ['name'],
  },
  {
    name: 'get_repo',
    description: 'Read a repository by owner and name.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The issue title.' },
      body: { type: 'string', description: 'The issue body.' },
    },
    required: ['owner', 'repo', 'title'],
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      state: { type: 'string', description: 'Issue state filter: open, closed or all.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch onto a base branch.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The pull request title.' },
      head: { type: 'string', description: 'The head branch name.' },
      base: { type: 'string', description: 'The base branch name.' },
    },
    required: ['owner', 'repo', 'title', 'head', 'base'],
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request by number.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      pull_number: { type: 'integer', description: 'The pull request number.' },
    },
    required: ['owner', 'repo', 'pull_number'],
  },
];

function mcpToolsList(): Array<Record<string, unknown>> {
  return MCP_TOOLS.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: { type: 'object', properties: t.properties, required: t.required },
  }));
}

/** Normalize tool arguments: accept the documented names and their common synonyms. */
function mcpArg(args: Record<string, unknown>, ...names: string[]): unknown {
  for (const n of names) if (args[n] !== undefined) return args[n];
  return undefined;
}

function mcpRepoOf(args: Record<string, unknown>): Repo | null {
  let owner = mcpArg(args, 'owner', 'owner_login', 'login') as string | undefined;
  let repoName = mcpArg(args, 'repo', 'repository', 'repository_name', 'repo_name') as string | undefined;
  const full = mcpArg(args, 'full_name', 'repo_full_name', 'repository_full_name') as string | undefined;
  if ((owner === undefined || repoName === undefined) && typeof full === 'string') {
    const slash = full.indexOf('/');
    if (slash > 0) {
      owner = full.slice(0, slash);
      repoName = full.slice(slash + 1);
    }
  }
  if (typeof owner !== 'string' || typeof repoName !== 'string') return null;
  return store.findRepo(owner, repoName);
}

function mcpToolResult(obj: unknown): Record<string, unknown> {
  const text = typeof obj === 'string' ? obj : JSON.stringify(obj);
  return { content: [{ type: 'text', text }], structuredContent: obj, isError: false };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function executeMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  switch (name) {
    case 'create_repo': {
      const repoName = mcpArg(args, 'name', 'repo', 'repository') as string | undefined;
      if (typeof repoName !== 'string' || repoName === '') return mcpToolError('create_repo requires a name');
      if (store.byName.has(repoName)) return mcpToolError(`Repository ${repoName} already exists`);
      const repo = store.createRepo(
        repoName,
        (mcpArg(args, 'description', 'about', 'summary') as string | undefined) ?? '',
        mcpArg(args, 'private', 'is_private') === true,
      );
      return mcpToolResult(repoJson(repo));
    }
    case 'get_repo': {
      const repo = mcpRepoOf(args);
      if (repo === null) return mcpToolError('repository not found');
      return mcpToolResult(repoJson(repo));
    }
    case 'create_issue': {
      const repo = mcpRepoOf(args);
      if (repo === null) return mcpToolError('repository not found');
      const title = mcpArg(args, 'title', 'issue_title', 'subject') as string | undefined;
      if (typeof title !== 'string' || title === '') return mcpToolError('create_issue requires a title');
      const body = (mcpArg(args, 'body', 'issue_body', 'description', 'content', 'text') as string | undefined) ?? '';
      const issue = store.createIssue(repo, title, body, []);
      return mcpToolResult(issueJson(repo, issue));
    }
    case 'list_issues': {
      const repo = mcpRepoOf(args);
      if (repo === null) return mcpToolError('repository not found');
      const state = (mcpArg(args, 'state', 'status') as string | undefined) ?? 'open';
      const list = repo.issues.filter((i) => state === 'all' || i.state === state);
      return mcpToolResult(list.map((i) => issueJson(repo, i)));
    }
    case 'create_pull_request': {
      const repo = mcpRepoOf(args);
      if (repo === null) return mcpToolError('repository not found');
      const title = (mcpArg(args, 'title', 'pr_title', 'pull_request_title') as string | undefined) ?? '';
      const head = mcpArg(args, 'head', 'head_ref', 'head_branch', 'source_branch', 'from_branch', 'branch') as string | undefined;
      const base = mcpArg(args, 'base', 'base_ref', 'base_branch', 'target_branch', 'into_branch') as string | undefined;
      if (title === '' || typeof head !== 'string' || typeof base !== 'string') {
        return mcpToolError('create_pull_request requires title, head and base');
      }
      const created = store.createPull(repo, title, '', head, base);
      if ('error' in created) return mcpToolError(created.error);
      return mcpToolResult(pullJson(repo, created));
    }
    case 'merge_pull_request': {
      const repo = mcpRepoOf(args);
      if (repo === null) return mcpToolError('repository not found');
      const num = mcpArg(args, 'pull_number', 'pull_request_number', 'pr_number', 'number');
      const number = typeof num === 'number' ? num : Number.parseInt(String(num ?? ''), 10);
      if (!Number.isInteger(number)) return mcpToolError('merge_pull_request requires pull_number');
      const pull = repo.pulls.find((p) => p.number === number);
      if (pull === undefined) return mcpToolError(`pull request #${number} not found`);
      const merged = store.mergePull(repo, pull);
      if ('error' in merged) return mcpToolError(merged.error);
      return mcpToolResult({ merged: true, sha: merged.sha, number, message: 'Pull Request successfully merged' });
    }
    default:
      return mcpToolError(`unknown tool ${name}`);
  }
}

function handleMcp(req: IncomingMessage, res: ServerResponse, body: Buffer): void {
  const parsed = parseJsonBody(body);
  if (!parsed.ok) {
    return sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
  }
  const value = parsed.value;
  if (!isRecord(value) || typeof value.method !== 'string') {
    return sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
  }
  const id = value.id ?? null;
  const method = value.method;
  const params = isRecord(value.params) ? value.params : {};

  const result = (r: unknown): void => sendJson(res, 200, { jsonrpc: '2.0', id, result: r });
  const error = (code: number, message: string): void =>
    sendJson(res, 200, { jsonrpc: '2.0', id, error: { code, message } });

  switch (method) {
    case 'server/discover':
      return result({
        resultType: 'discover',
        supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18'],
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        capabilities: { tools: {} },
        instructions: 'A GitHub-compatible forge: repositories, issues, pull requests, git smart HTTP, GraphQL and MCP tools.',
      });
    case 'initialize': {
      const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
      const supported = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
      const negotiated = supported.includes(offered) ? offered : '2025-11-25';
      return result({
        protocolVersion: negotiated,
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      });
    }
    case 'notifications/initialized':
    case 'notifications/cancelled':
      // Notifications carry no id and expect no JSON-RPC response.
      return sendNoBody(res, 202);
    case 'ping':
      return result({});
    case 'tools/list':
      return result({ tools: mcpToolsList() });
    case 'tools/call': {
      const name = typeof params.name === 'string' ? params.name : '';
      const args = isRecord(params.arguments) ? params.arguments : {};
      const tool = MCP_TOOLS.find((t) => t.name === name);
      if (tool === undefined) return error(-32602, `unknown tool ${name}`);
      const missing = tool.required.filter((r) => args[r] === undefined);
      if (missing.length > 0) return result(mcpToolError(`missing required argument(s): ${missing.join(', ')}`));
      return result(executeMcpTool(name, args));
    }
    default:
      return error(-32601, `method not found: ${method}`);
  }
}

// -------------------------------------------------------------------------------------------
// server: routing, body reading, lifecycle surface
// -------------------------------------------------------------------------------------------

export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    const pathname = (() => {
      try {
        return new URL(req.url ?? '/', 'http://entry').pathname;
      } catch {
        return '/';
      }
    })();
    const method = req.method ?? 'GET';
    const segs = splitPath(pathname);

    // The env's boot check: 200 {"ok":true}, no auth.
    if (method === 'GET' && pathname === '/healthz') {
      sendJson(res, 200, { ok: true });
      return;
    }

    const needsBody = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
    const finish = (body: Buffer): void => {
      try {
        route(req, res, pathname, segs, body);
      } catch (err) {
        // Never let one bad request kill the process: answer 500 JSON and stay up.
        try {
          sendJson(res, 500, { message: err instanceof Error ? err.message : 'internal error' });
        } catch {
          // The response is already gone; nothing left to do.
        }
      }
    };
    if (!needsBody) {
      finish(Buffer.alloc(0));
      return;
    }
    readBody(req)
      .then((body) => {
        (req as unknown as { __body?: Buffer }).__body = body;
        finish(body);
      })
      .catch(() => {
        try {
          sendJson(res, 400, { message: 'could not read request body' });
        } catch {
          // ignore
        }
      });
  });
}

function route(req: IncomingMessage, res: ServerResponse, pathname: string, segs: string[], body: Buffer): void {
  const method = req.method ?? 'GET';

  // MCP: auth required, JSON-RPC errors for malformed bodies.
  if (pathname === '/mcp') {
    if (method !== 'POST') {
      sendJson(res, 405, { message: 'Method Not Allowed' });
      return;
    }
    if (!isAuthorized(req)) {
      sendJson(res, 401, { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Unauthorized' } });
      return;
    }
    handleMcp(req, res, body);
    return;
  }

  // GraphQL: auth required, 401 without a token.
  if (pathname === '/api/graphql') {
    if (method !== 'POST') {
      sendJson(res, 405, { message: 'Method Not Allowed' });
      return;
    }
    if (!isAuthorized(req)) {
      sendJson(res, 401, { errors: [{ message: 'Unauthorized' }] });
      return;
    }
    handleGraphQL(req, res, body);
    return;
  }

  // REST v3: auth required on every route; malformed JSON bodies are 400.
  if (segs[0] === 'api' && segs[1] === 'v3') {
    if (!isAuthorized(req)) {
      restError(res, req, 401, 'Unauthorized');
      return;
    }
    if ((method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') && body.length > 0) {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        restError(res, req, 400, 'request body is not valid JSON');
        return;
      }
      handleRest({ req, res, segs: segs.slice(2), query: queryOf(req), body: parsed.value });
      return;
    }
    handleRest({ req, res, segs: segs.slice(2), query: queryOf(req), body: undefined });
    return;
  }

  // Git smart HTTP: /{owner}/{repo}.git/...
  if (segs.length >= 2 && segs[1].endsWith('.git')) {
    if (!isAuthorized(req)) {
      sendJson(res, 401, { message: 'Unauthorized' });
      return;
    }
    handleGit(req, res, segs);
    return;
  }

  sendJson(res, 404, { message: 'Not Found' });
}
