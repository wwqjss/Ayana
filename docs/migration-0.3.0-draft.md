# Ayana 0.3.0 Schema Migration Draft (requirements only)

**Status:** draft · Phase A · do **not** apply to production  
**Goal:** define what must change; implementation is Phase B/C.

## Principles

- SQLite stays the store; migrations are ordered and versioned.
- Markdown `knowledge/*.md` remains the knowledge source of truth.
- No dual-written human-editable knowledge bodies.

## Version table (new)

```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at REAL NOT NULL,
  checksum TEXT NOT NULL DEFAULT ''
);
```

Current DB is effectively `version=1` (implicit / existence patching).

## Migration 2 — P0-02 action authorization snapshot

Add to `actions` (or `action_authz` child table):

| column | purpose |
|--------|---------|
| `mode` | `manual` \| `auto` |
| `runbook_id` | matched rule or `manual-template:<name>` |
| `runbook_rev` | rule/template version at propose time |
| `object_ref` | normalized `asset:kind:name` |
| `binding_rev` | asset binding / host_id_verified_at snapshot |
| `params_digest` | hash of tokens/params |
| `authz_snapshot_json` | policy decision + rule id + versions |
| `approval_deadline` | explicit TTL end |

**Acceptance:** re-dispatch after policy tighten / template change / expired approval must reject and audit reason.

## Migration 3 — P0-03 preconditions & budget

| column / table | purpose |
|----------------|---------|
| `actions.precondition_json` | satisfied/unsatisfied/unknown + probe evidence |
| `actions.budget_claimed_at` | claimed **before** dispatch |
| `global_stops` | persistent pause/maintenance at dispatch |
| atomic object/budget claim | at final dispatch |

**Acceptance:** investigation failure / stale probe / pause / exhausted budget ⇒ zero auto-dispatch.

## Migration 4 — P0-04 incident outcome / generation

On `incidents`:

| column | purpose |
|--------|---------|
| `generation` | increments on re-fire |
| `outcome` | `recovered` \| `unrecovered` \| `unknown` \| `closed_unverified` |
| `resolution_basis` | verification id / manual / AM |
| `closed_at` / `close_reason` | distinct from `resolved_at` |

**Acceptance:** `passed` cannot `resolve` while firing episode, unknown action, or need_human remains (unless explicit generation supersede).

## Migration 5 — P0-05 verification profiles

| column | purpose |
|--------|---------|
| `verifications.profile_id` | e.g. `frps.recover`, `svc.stop` |
| `metric` / selector | not hardcoded `probe_success` only |
| `deadline_at` | fixed, not restarted each loop |
| `stability_sec` | true consecutive-success duration |
| `warmup_sec` / `sample_gap_max` | startup grace; gap ⇒ inconclusive |

Profiles reviewed in code/config, not model PromQL.

## Migration 6 — P0-06 observation inventory

| table | purpose |
|-------|---------|
| `object_checks` | required check per object + freshness_max |
| `object_observations` (optional) | last sample, staleness |

**Acceptance:** missing/stale/incomplete required checks ⇒ `unknown`/`unobserved`, never green.

## Migration 7 — P0-01 runtime identity (ops, not SQL)

- non-root `ayana` + systemd + single-instance lock
- host gate root-owned, not app-writable
- config perms tightened
- own SSH identity per asset

## Non-goals (0.3.0)

No FTS5/vector DB requirement; no multi-tenant RBAC; no auto knowledge promotion. Drop legacy `object_knowledge` only after MD is sole writer.

## Production baseline (Phase A read-only)

| item | value |
|------|--------|
| Deploy | KANATA `/root/Ayana`, root + setsid, no `ayana.service` |
| Ports | 6200/6199 on `0.0.0.0` |
| Auto remediation | false |
| Incidents | 7 (4 resolved, 2 closed, 1 open/pending) |
| Actions | 8 (7 success, 1 cancelled) |
| Verifications | 9 passed (historical) |
| Objects | 10; Yomi none; sora google/youtube not registered |
| Monitor | nerv frps/nginx probe_success; kanata harbor vs harbor-core; sora hysteria_proxy_up |
| Knowledge | 3 active MD |
