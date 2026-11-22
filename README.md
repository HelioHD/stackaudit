# stackaudit

> Read this in [Português (pt-BR)](./README-pt-BR.md).

A passive-first CLI that audits small apps deployed on **Supabase + Vercel + Render**
for misconfigurations and emits findings that drop straight into a pentest report.

`npx stackaudit <url>` looks at what a browser already receives — the JS bundle, HTTP
headers, source maps, `/.env`, `/.git/config` — detects the platform stack, and reports
what is exposed. An opt-in **active** mode proves Supabase table exposure *without
downloading a single row*.

It is part of the **Delfino Security** toolchain and emits the shared
[`finding.schema.json`](./schema/finding.schema.json), so its output feeds the report
generator (and interoperates with `sealcheck`, the sibling JWT tool) with no manual glue.

---

## Legal posture (read this first)

This tool is built to be run against systems you are allowed to test. The defaults are
conservative on purpose.

| Mode | Needs | What it does |
|---|---|---|
| **passive** (default) | a URL | Only what a browser already downloads: bundle, headers, source maps, `/.env`, `/.git/config`, `/.well-known`. No auth, no API calls. |
| **active** (`--authorized`) | a URL **and** the explicit `--authorized` flag | May query the Supabase public (anon) endpoint with **`HEAD` + `Prefer: count=exact`**, reading the row total from the `Content-Range` header. |
| **config** (v2) | platform owner tokens | Out of scope for this MVP. Stubbed; it exits with a notice. |

Hard guarantees, enforced in code and covered by tests:

- **Count, never read.** Active table checks use `HEAD` + `Prefer: count=exact`. The total
  comes from `Content-Range`; **no rows are ever downloaded**. A test asserts every
  `/rest/v1` request is a `HEAD`.
- **`200 []` does not prove RLS is off.** RLS enabled with no matching policy also returns
  empty. The output says so and marks that case for manual review.
- **Write permissiveness is not tested.** INSERT/UPDATE are never attempted — testing them
  means writing to someone else's database.
- **Secrets are reported, never exercised.** A discovered Stripe/AWS/Supabase key is
  redacted and reported. The tool **never** validates it by calling the owner's API — that
  would itself be use of the credential. A test asserts no discovered secret is sent anywhere.

---

## 2-minute quick start

```bash
# passive scan (default), human-readable output
npx stackaudit https://your-app.example

# machine output for a report pipeline
npx stackaudit https://your-app.example --format json  -o findings.json
npx stackaudit https://your-app.example --format sarif -o results.sarif
npx stackaudit https://your-app.example --format html  -o report.html

# active mode — requires explicit authorization, Supabase count only
npx stackaudit https://your-app.example --mode active --authorized
```

From source:

```bash
npm install
npm run build
node dist/cli.js https://your-app.example
npm test
```

---

## Example output (captured on local fixtures)

The snippets below were produced by running stackaudit against the test fixture in
[`test/fixtures.ts`](./test/fixtures.ts) — a fake app with planted, obviously-fake secrets.
The full captures live in [`examples/`](./examples).

### Terminal

```
../ stackaudit  https://demo-app.example
mode: active   platforms: vercel, supabase   requests: 14

CRITICAL 3  HIGH 5  MEDIUM 6  LOW 3  INFO 6

[CRITICAL] Supabase secret key (sb-secret, role=service_role) in client bundle
    A secret-grade Supabase key (sb_sec...0000) was found in https://demo-app.example/assets/app.js. This key bypasses RLS and grants full database access.
    affected: https://demo-app.example/assets/app.js
    status: confirmed   check: supabase-key-in-bundle

[HIGH] Sensitive table "users" exposes 1452 rows to the anon key
    HEAD + Prefer: count=exact on users returned Content-Range total 1452 using only the public key. No rows were downloaded. The table name suggests personal data. INSERT/UPDATE permissiveness is NOT tested (never written).
    affected: https://abcdefghijklmnopqrst.supabase.co/rest/v1/users?select=*
    status: confirmed   check: supabase-table-count

[REVIEW] Review: Table "products" exposes 320 rows to the anon key
    ... Name does not suggest personal data (a public product catalog may be intentional); classify manually.
```

Severity words are always written (never colour alone), colours follow the Delfino CLI
palette, and `NO_COLOR` is respected.

### HTML

A single self-contained page using the Delfino UI tokens (Space Grotesk + IBM Plex Mono,
`#0057FF` accent, severity colours, light/dark). See
[`examples/report.html`](./examples/report.html).

### JSON

Each finding validates against [`schema/finding.schema.json`](./schema/finding.schema.json):

```json
{
  "schemaVersion": 1,
  "id": "SA-01",
  "title": "Supabase secret key (sb-secret, role=service_role) in client bundle",
  "status": "confirmed",
  "severity": "critical",
  "cwe": "CWE-312",
  "owasp": "A05:2021",
  "affected": ["https://demo-app.example/assets/app.js"],
  "tool": { "name": "stackaudit", "version": "0.1.0" },
  "fingerprint": "sha256:..."
}
```

---

## Checks (MVP)

**Supabase**
- Secret key in the bundle — detects **both** the legacy JWT format (decoded; the `role`
  claim is read, not regex-guessed) and the new `sb_secret_` / `sb_publishable_` prefixes.
- *(active)* Table row counts via `HEAD` + count, with sensitivity classification
  (names suggesting email/cpf/phone → **HIGH**, otherwise → **REVIEW**).
- *(active)* Listable storage bucket (the list is a `POST`; "read-only" is stated to include it).
- *(active)* `GET /auth/v1/settings` — open signup / autoconfirm.
- *(active)* `pg_graphql` endpoint presence and client-referenced RPCs to review for
  `SECURITY DEFINER` misuse.

**Vercel / front**
- Secrets in the bundle using the **gitleaks** rule set (see below).
- Public source maps.
- Security headers (CSP, HSTS, `frame-ancestors` / clickjacking, Referrer-Policy) — headers
  are audited **only here**.
- Origin bypass via a reachable `*.vercel.app`.

**Render / API**
- `/.env`, `/.git/config`, `/.git/HEAD` exposure.
- Reflected CORS with credentials.
- Stack trace leaked in production.
- Origin bypass via a reachable `*.onrender.com`.

Every check is a plugin with metadata: `id`, `platform`, `modeRequired`, `defaultSeverity`,
`reference`, `remediation` (see [`src/checks`](./src/checks)).

---

## Honest positioning

stackaudit does **not** replace these — it fills the gap between them:

- **supasec** (`npx supasec scan`) and other Supabase scanners audit Supabase in isolation.
- The **Supabase Security Advisor** runs Postgres lints (the `splinter` rule set, e.g.
  `0013_rls_disabled_in_public`) from *inside* the project, with owner access.

What stackaudit adds: the **three platforms audited together** (the real stack of a small
Brazilian app), **origin bypass**, and output in the **shared report schema**. It proves
exposure *from the outside, without touching the data*. The planned **config** mode will
run `splinter` rather than reimplementing those lints — the official source is the right
one to reuse.

> "Checks focused on the BaaS misconfigurations that generic scanners don't model, proving
> exposure without touching the data."

---

## Why this architecture

| Decision | Choice | Rejected | Why |
|---|---|---|---|
| Language | **TypeScript / npx** | Go, Python | These platforms' community lives in the JS/TS ecosystem; `npx` means zero-install. The constraint set here is Node-only (no Python, no Go). |
| Structure | **plugins with metadata** | one monolithic scanner | The platforms change fast; each check updates in isolation and carries its own severity, mode and remediation. |
| RLS test | **`HEAD` + count** | read rows and "don't save them" | Proves exposure without downloading anyone's personal data. The only legally safe way to demonstrate a readable table. |
| Default mode | **passive** | active by default | Passive does only what a browser would. Anything that touches an API requires an explicit, logged `--authorized`. |
| config mode | **v2, reusing splinter** | reimplement the lints | Three APIs that change without notice would triple maintenance; `splinter` is already the official source. |
| Output | **shared `finding.schema.json`** | a bespoke format | One tool feeds the next (report generator, `sealcheck`) with no manual glue. |

### Why each dependency

- **TypeScript** — types catch check-plugin mistakes (wrong severity, missing field) at
  build time; the finding shape is enforced by the compiler before Ajv ever runs.
- **ajv** + **ajv-formats** (JSON Schema 2020-12) — the shared schema is the contract with
  the rest of the toolchain. Every emitted finding is validated against the *byte-identical*
  schema in tests, so a drift breaks the build, not a downstream report.
- **gitleaks rules (vendored, not the binary)** — secret detection is a solved problem;
  hand-rolled regexes are how scanners get false negatives. A curated subset of gitleaks'
  open-source regex rules (MIT, config at tag **v8.21.2**,
  <https://github.com/gitleaks/gitleaks>) is vendored into
  [`src/gitleaks/rules.ts`](./src/gitleaks/rules.ts) as data. No gitleaks binary is
  required and nothing is fetched at runtime.
- **vitest** (dev only) — the whole suite is **network-free**: fixtures for bundles,
  headers, source maps and `.env`/`.git` responses, plus a mock HTTP layer that records
  every request so tests can assert no rows are downloaded and no secret is ever sent.
- **tsx** (dev only) — run the CLI from source without a build step.

Runtime dependencies are intentionally only `ajv` + `ajv-formats`. HTTP uses Node's global
`fetch` (Node 20+); no HTTP client dependency.

---

## Output formats

- `--format terminal` (default) — human summary; Delfino CLI palette; `NO_COLOR` honoured.
- `--format json` — array of findings validating against `schema/finding.schema.json`.
  Findings default to `status: unconfirmed` unless the evidence proves them; the `REVIEW`
  concept maps to severity `info` with a `Review:` title prefix (the schema enum is
  critical/high/medium/low/info).
- `--format sarif` — SARIF 2.1.0 for the GitHub Security tab.
- `--format html` — one-page report using the Delfino UI tokens.

---

## Development

```bash
npm install
npm run build       # tsc -> dist/
npm test            # vitest, network-free
npm run typecheck
```

CI is defined in [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) (actions pinned by
commit SHA, minimal `contents: read` permissions). **It has not been executed here** — it
runs on push/PR once the repo is on GitHub.

## Security & license

See [`SECURITY.md`](./SECURITY.md). Licensed under [MIT](./LICENSE), © 2026 Hélio Delfino.
