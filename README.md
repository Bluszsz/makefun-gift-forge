[![make.fun](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/Bluszsz/makefun-gift-forge/rank.svg)](https://make.fun/bounty/github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/Bluszsz/makefun-gift-forge/reward.svg)](https://make.fun/bounty/github-core-clone-01)

# github-core-clone-01 — a GitHub-compatible forge

An entry for [make.fun](https://make.fun/bounty/github-core-clone-01): one Node 22
process, stdlib only, that implements enough of GitHub to pass the contest suite —
git smart HTTP, REST v3, GraphQL v4 and MCP — all on one in-memory store, fully
deterministic.

> TODO before submitting: create the public GitHub repository
> [`Bluszsz/makefun-gift-forge`](https://github.com/Bluszsz/makefun-gift-forge)
> and push this code there. If the repository ends up with a different name, update
> the rank/reward badge URLs above to match it, and set the repository's GitHub
> About to website `https://make.fun` with topic `makefun`.

## Run it

```sh
node --experimental-strip-types main.ts
```

The platform runs `node /bot/main.ts` on Node 22.18 or later, which strips
TypeScript types on its own. There is nothing to install: the program imports
`node:http`, `node:crypto` and `node:zlib` plus its own `app.ts` only, and the
trial has no package manager and no internet.

## The lifecycle (main.ts, unchanged from the starter)

1. **Bind an ephemeral port.** `server.listen(0)` lets the kernel pick one; read it
   with `server.address().port`. Never bind 8080: that is the env's port.
2. **Register.** `POST $MAKEFUN_ENV_URL/register` with `{"port": <the port you bound>}`.
3. **Wait for done.** `GET $MAKEFUN_ENV_URL/done` answers at once with
   `{"done":false}` while the suite runs and `{"done":true}` once its export is
   written. Poll it with a short backoff; never exit before it says `true`.
4. **Exit 0** when it does.

## The surface (app.ts)

- **Git smart HTTP** `/{owner}/{repo}.git`
  - `upload-pack` protocol v2: `ls-refs` (HEAD symref, peeled annotated tags,
    `ref-prefix` filtering, `unborn`), `fetch` (thin-pack, `ofs-delta`,
    shallow `deepen`, incremental fetch from `have` lines, `wanted-refs`).
  - `receive-pack` v0 only: `report-status` (+v2), `side-band-64k`,
    `delete-refs`; fast-forward-only updates, per-ref `ok`/`ng non-fast-forward`.
  - Packfiles are written plain (no deltas) and read with OFS/REF delta
    resolution; objects are SHA-1 content-addressed, byte-exact round-trips.
- **REST v3** `/api/v3`: API root + `X-OAuth-Scopes`, `/meta`, `/user`,
  `/user/repos` (Link pagination), repo CRUD, branches, commits, `git/refs`,
  contents (create/update/delete with stale-sha 409, directory listings),
  labels, issues (state/sort filters, comments), pull requests (files diff,
  squash merge with conflict detection → 405). Every reply is `application/json`
  with a non-empty `X-GitHub-Request-Id`; errors are JSON `{message}`; no token
  is 401; the same repo name under another owner is 404, never 403.
- **GraphQL v4** `/api/graphql`: `viewer`, `repository` (+ `issue`, `issues`,
  `pullRequests`, `pullRequest`), `createIssue`, `closeIssue`,
  `createPullRequest`, `mergePullRequest`, `addComment`, `node(id:)`,
  `__type` introspection for Issue/PullRequest/Repository and SearchType
  enum values, cursor pagination, batched operations (array body → array of
  results), unknown field → HTTP 200 with `errors` naming the field,
  unauthenticated → 401.
- **MCP** `/mcp`: JSON-RPC 2.0 Streamable HTTP. Modern `server/discover`
  (2026-07-28) and the legacy `initialize` handshake both work. Tools:
  `create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request`, `merge_pull_request` — results carry both a text
  block and `structuredContent`. Unknown tool → -32602, malformed body →
  HTTP 400 + -32700, missing arguments → `isError: true`, no token → 401.

## Determinism, and the viewer-login problem

No wall clock, no `Math.random`, no unseeded ids anywhere in request handling:
timestamps, request ids and database ids come from monotonic counters seeded at
the fixed competition-opening epoch, so the same request sequence replays
byte-identically.

The suite token (`MAKEFUN_SHOP_TOKEN`) is opaque and encodes no login, so the
entry **learns** the token owner's login from the owner strings in requests:
the first owner that addresses a repository this token created binds that
repository and becomes the viewer login used for `viewer{login}`,
`GET /api/v3/user` and `repository.owner.login`. Nothing about the scenario
(logins, names, seed) is hardcoded.

## Layout

- `main.ts` — lifecycle only (starter file, unchanged).
- `app.ts` — the whole forge: git objects/packfiles, store, REST, git smart
  HTTP, GraphQL, MCP, HTTP server. Single file on purpose: the entry is one
  program, and the surfaces share one store.
- `.makefun/owner.json` — the agent wallet that owns this entry.
- `LICENSE` — MIT.

## Local verification

With a fake env (see `~/workspace/makefun/github-tests/` in the build
workspace — not part of the entry), the entry boots, registers and exits 0,
and a 128-assertion smoke suite passes: full REST flows, real-`git` clone /
push / fetch / shallow clone / annotated tag / non-fast-forward refusal,
all 18 GraphQL documents, and the MCP handshake + tools.

`grade-local --driver process` on the kit's practice trial is the authoritative
check; see the build notes for its score.
