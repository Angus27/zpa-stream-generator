# ZPA detection lab — using the synthetic data to derive detection rules

This guide is for one specific goal: **stand up the synthetic ZPA data in
Elasticsearch, point an Elastic agent (AI Assistant for Security / Attack
Discovery / Agent Builder) at it, and let the agent work out what the detection
rules should be** — then check the agent's answers against the anomalies you
*know* were planted.

It complements [ZPA_STREAM_README.md](ZPA_STREAM_README.md), which is the full
operating manual for the streamer itself. Read that for setup/CLI detail; read
**this** for the data model, the ground truth, and the agent workflow.

---

## The workflow at a glance

```
  zpa_stream_generator.py ──▶  Elasticsearch data streams
                               • zpa-user-activity-logs
                               • zpa-user-status-logs
                                      │
                                      ▼
                          Kibana data views (queryable)
                                      │
                                      ▼
                 Elastic agent  ── "what should we detect here?"
                 (given the data + the authorization baseline below)
                                      │
                                      ▼
                    Proposed detection rules (ES|QL / KQL / EQL)
                                      │
                                      ▼
        Validate against ground truth  (zpa.anomaly.flag = the answer key)
```

The data is **labeled**: every event the generator considers anomalous carries
`zpa.anomaly.flag` and `zpa.anomaly.is_anomalous: true`. Treat those as the
**answer key**, not as a detection signal (see
[Don't let the agent cheat](#dont-let-the-agent-cheat)).

---

## Step 1 — Stand up the data

Condensed; see the README for full detail.

```bash
export ELASTIC_ENDPOINT="https://my-cluster:9200"
export ELASTIC_API_KEY="<base64 id:api_key from Kibana>"

python zpa_stream_generator.py --init-users     # once: build the user pool
python zpa_stream_generator.py --setup          # once: templates + data streams
python zpa_stream_generator.py                  # stream continuously
```

Let it run for a while (tens of minutes to hours) so there's enough normal
traffic for "normal" to be statistically obvious and enough anomalies to detect.
To force a concentrated burst of a particular anomaly on demand, arm a scenario
in `zpa_scenarios.yaml` (see [Creating labeled incidents](#creating-labeled-incidents-on-demand)).

---

## Step 2 — Make the data queryable in Kibana

Create two data views (Stack Management → Data Views), or one combined:

| Data view name | Index pattern | Time field |
|---|---|---|
| ZPA activity | `zpa-user-activity-logs` | `@timestamp` |
| ZPA status | `zpa-user-status-logs` | `@timestamp` |
| ZPA all (optional) | `zpa-user-*-logs` | `@timestamp` |

Confirm documents are landing in Discover before involving the agent.

---

## The data model (give this to the agent)

Two data streams, ECS-mapped, with a `zpa.*` namespace for product-specific
fields.

### `zpa-user-activity-logs` — per-connection records

| Field | Type | Meaning |
|---|---|---|
| `@timestamp` | date | Event time (UTC) |
| `event.action` | keyword | `allow` / `deny` |
| `event.outcome` | keyword | `success` / `failure` (failure = denied) |
| `event.category` | keyword | `["network"]` |
| `event.dataset` | keyword | `zpa.activity` |
| `user.id` / `user.name` / `user.email` | keyword | User identity |
| `user.roles` | keyword[] | The user's role (e.g. `noc_engineer`) |
| `user.domain` | keyword | Internal domain |
| `source.ip` | ip | Client device IP |
| `source.bytes` | long | Bytes sent by client |
| `destination.domain` | keyword | Target app FQDN |
| `destination.port` | long | Target port |
| `destination.bytes` | long | Bytes returned |
| `network.transport` / `network.protocol` | keyword | `tcp` |
| `network.bytes` | long | Total bytes |
| `observer.name` / `observer.ip` | keyword / ip | ZPA connector group serving the session |
| `zpa.department` | keyword | User's department |
| `zpa.application_segment` | keyword | **Segment accessed** (the key authz field) |
| `zpa.app_host` | keyword | App host (also `destination.domain`) |
| `zpa.policy_action` | keyword | `Allow` / `Deny` |
| `zpa.posture.check` | keyword | `Pass` / `Fail` |
| `zpa.session.duration_seconds` | long | Session length (0 if denied) |
| `zpa.connector.group` / `zpa.connector.ip` | keyword / ip | Connector serving the session |
| `zpa.idp.provider` | keyword | Identity provider |
| `zpa.anomaly.is_anomalous` | boolean | **Answer key** — true if planted |
| `zpa.anomaly.flag` | keyword | **Answer key** — anomaly type |
| `zpa.anomaly.detail` | text | **Answer key** — human-readable reason |

### `zpa-user-status-logs` — session lifecycle events

| Field | Type | Meaning |
|---|---|---|
| `@timestamp` | date | Event time (UTC) |
| `message` | text | Status detail |
| `event.action` | keyword | Lowercased event type (e.g. `zpa_auth_failure`) |
| `event.outcome` | keyword | `success` / `failure` |
| `event.category` | keyword | `["authentication"]` or `["session"]` |
| `event.dataset` | keyword | `zpa.status` |
| `user.id` / `user.name` / `user.email` | keyword | User identity |
| `user.roles` | keyword[] | Role |
| `user.group.name` | keyword | Department |
| `source.ip` | ip | Client IP |
| `host.name` | keyword | Device (username-derived) |
| `host.os.full` | keyword | OS platform |
| `agent.name` / `agent.version` | keyword | `zpa-client` + version |
| `zpa.event_type` | keyword | Raw ZPA event (e.g. `ZPA_AUTH_FAILURE`) |
| `zpa.posture.status` | keyword | `Pass` / `Fail` |
| `zpa.cloud` | keyword | ZPA cloud endpoint |
| `zpa.connector.group` | keyword | Connector group |
| `zpa.idp.provider` / `zpa.idp.group` | keyword | IdP context |
| `zpa.session.duration_seconds` | long | Set on disconnect/timeout events |
| `zpa.anomaly.is_anomalous` / `zpa.anomaly.flag` / `zpa.anomaly.detail` | — | **Answer key** |

### Status event types

`ZPA_CLIENT_CONNECTED`, `ZPA_CLIENT_DISCONNECTED`, `ZPA_AUTH_SUCCESS`,
`ZPA_AUTH_FAILURE`, `ZPA_POSTURE_FAIL`, `ZPA_TUNNEL_ESTABLISHED`,
`ZPA_TUNNEL_TORN_DOWN`, `ZPA_IDP_TOKEN_REFRESH`, `ZPA_CLIENT_IDLE_TIMEOUT`.

---

## The authorization baseline (essential agent context)

An agent **cannot** judge "over-privileged" or "cross-segment" access without
knowing who is *supposed* to reach what. This is the expected-access model the
data is generated from (source of truth: `zpa_log_config.yaml`). Provide it to
the agent verbatim — it is the policy the agent is implicitly reverse-engineering.

| Segment | Expected roles (legitimate access) | Dormant? | Sensitive crossing? |
|---|---|:--:|---|
| `SEG-CORP-INTRANET` | **all roles** | no | — |
| `SEG-NOC-OPS` | noc_engineer, noc_manager, ot_manager, sre, soc_manager, infra_manager | no | — |
| `SEG-OSS-BSS` | oss_engineer, bss_analyst, bss_manager | no | — |
| `SEG-NETWORK-MGMT` | noc_engineer, noc_manager, infra_manager | no | flag bss_analyst, finance_analyst, hr_analyst |
| `SEG-SCADA-OT` | ot_engineer, ot_manager | no | flag noc_engineer, devops_engineer, sre, bss_analyst |
| `SEG-FINANCE-ERP` | finance_analyst, finance_manager, cfo, bss_manager, hr_manager, ciso | no | flag ot_engineer, noc_engineer, devops_engineer |
| `SEG-HR-SYSTEMS` | hr_analyst, hr_manager, hrbp, finance_manager, cfo | no | — |
| `SEG-DEVOPS-CI` | devops_engineer, sre, dev_lead, api_dev | no | — |
| `SEG-SECURITY-TOOLS` | soc_analyst, soc_manager, ciso | no | flag bss_analyst, finance_analyst, ot_engineer |
| `SEG-LEGACY-BILLING` | *(none active)* | **yes** | any access is anomalous |
| `SEG-DR-STANDBY` | noc_manager, infra_manager | **yes** | any access is anomalous |
| `SEG-WHOLESALE-API` | wholesale_mgr, api_dev | **yes** | any access is anomalous |

> **Detection principle:** an `Allow` to a segment by a role *not* in that
> segment's expected-roles list is over-privileged access. Some role→segment
> crossings into sensitive systems (OT, Finance, Security, Network-Mgmt) are
> additionally singled out as cross-segment. Any traffic to a **dormant**
> segment is anomalous by definition.

> **Which list is authoritative?** The "expected roles" column above is each
> role's `primary_segs` from `zpa_log_config.yaml` — this is what the generator
> uses to decide normal vs over-privileged, so **grade against it**. Each segment
> also has an `authorised_roles` field (policy-as-written) that is slightly
> narrower in a few cases (e.g. `SEG-FINANCE-ERP` lists only finance roles, yet
> `bss_manager`/`hr_manager`/`ciso` legitimately carry it in `primary_segs`).
> That gap is realistic policy drift — don't treat those as anomalies; only the
> `primary_segs` baseline drives the labels.

---

## Ground truth — what the agent should rediscover

Six anomaly classes are planted. This is the answer key: the behaviour, the
fields that *signal* it (without using the `zpa.anomaly.*` labels), the rule
logic a good analyst/agent should land on, and the label used to grade it.

| # | Anomaly | Stream | Behaviour | Behavioural signal (no labels) | Sketch of the rule | Ground-truth label |
|---|---|---|---|---|---|---|
| 1 | **Over-privileged access** | activity | A flagged user repeatedly `Allow`s into segments outside their role | `zpa.application_segment` not in the role's expected set for `user.roles`; same `user.name` recurs | For each event, check segment ∉ expected-roles(role); alert, and escalate on repeat offenders | `OVER_PRIVILEGED` |
| 2 | **Cross-segment (sensitive)** | activity | A role reaches a *sensitive* segment it should never touch | `user.roles` ∈ the "sensitive crossing" set for that `zpa.application_segment` | Match the specific role→sensitive-segment pairs (SCADA/Finance/Security/Net-Mgmt) | `CROSS_SEGMENT` |
| 3 | **Dormant segment traffic** | activity | Any access to a decommissioned-but-still-published segment | `zpa.application_segment` ∈ {LEGACY-BILLING, DR-STANDBY, WHOLESALE-API} | Alert on *any* hit to a dormant segment | `DORMANT_SEGMENT` |
| 4 | **Denied access attempts** | activity | Policy blocks an access try (possible probing) | `event.action: deny` / `event.outcome: failure`; cluster by `user.name` / `source.ip` | Threshold of denials per user/IP over a window | `ACCESS_DENIED` |
| 5 | **Ghost user** | status | User authenticates (and refreshes tokens) but never opens an app session | `user.name` present in **status** with auth events, **absent from activity** over the same window | Set difference: authenticated users − users with activity | `GHOST_USER` |
| 6 | **Auth-failure / posture-fail bursts** | status | Spikes of `ZPA_AUTH_FAILURE` (credential stuffing) or `ZPA_POSTURE_FAIL` | `event.action: zpa_auth_failure` / `zpa.posture.status: Fail`; volume spike per user/IP | Threshold/rate rule per `user.name` or `source.ip` | `auth_failure` / `posture_fail` |

The flagged populations are stable across the run (8 over-privileged users, 4
ghost users by default, in `zpa_users.yaml`), so rules keyed on **repeat
offenders** are both fair and effective — that's the point of the
flagged-population model.

---

## Don't let the agent cheat

The documents include `zpa.anomaly.flag`, `zpa.anomaly.is_anomalous`, and
`zpa.anomaly.detail`. These are **labels for grading**, not detection signals. A
rule like `WHERE zpa.anomaly.flag IS NOT NULL` would score 100% and teach you
nothing.

There are two ways to keep the agent honest:

**Option A — brief it to ignore the labels.** Simplest; the labels stay in the
index for grading:

> "Build detections from behavioural fields only. The `zpa.anomaly.*` fields are
> a hidden answer key — do not reference them in any rule."

**Option B — run blind (recommended).** Stream with the answer-key fields
**omitted from the index entirely**, so the agent physically cannot see them:

```bash
python zpa_stream_generator.py --no-anomaly-labels
```

or set `streaming.include_anomaly_fields: false` in `zpa_log_config.yaml`. The
flagged users still *behave* anomalously (over-privileged access, ghost
sessions, etc.) — only the `zpa.anomaly.*` labels are dropped; all behavioural
fields remain. The startup banner prints `BLIND mode` as a reminder.

For grading, re-run **with** labels (default), or run a second labeled stream
into a separate set of indices, and evaluate as in
[Step 4](#step-4--validate-the-agents-rules-against-ground-truth). A clean
pattern: a blind run for the agent to discover rules, then a labeled run to
score them.

---

## Step 3 — Point an Elastic agent at the data

Exact UI varies by Elastic version; the shape of the task is the same.
Whichever surface you use (AI Assistant for Security, Attack Discovery, or a
custom Agent Builder agent), the agent needs three things in its context:

1. **Where the data is** — the `zpa-user-activity-logs` and
   `zpa-user-status-logs` data streams / data views.
2. **The data dictionary** — the field tables above (paste them, or attach this
   file / `ZPA_STREAM_README.md`).
3. **The authorization baseline** — the segment→expected-roles table and the
   dormant/sensitive flags. Without it the agent can't reason about privilege.

### Example prompts

Discovery:

> "You are a detection engineer. Two data streams (`zpa-user-activity-logs`,
> `zpa-user-status-logs`) hold Zscaler Private Access logs for our org. Here is
> the access-authorization baseline: «paste the segment→roles table». Using only
> behavioural fields (ignore any `zpa.anomaly.*` fields), profile normal
> behaviour, then identify anomalous patterns that warrant detection rules.
> For each, propose an ES|QL or KQL rule, the fields it keys on, a severity, and
> the false-positive risk."

Targeted, one class at a time (often higher quality):

> "In `zpa-user-activity-logs`, find users accessing application segments their
> role is not authorised for, given «authorization table». Return the offending
> users, the segments, the frequency, and a draft ES|QL detection."

Status / identity:

> "In `zpa-user-status-logs`, find accounts that authenticate but never appear
> in `zpa-user-activity-logs` over the same window. Propose a rule to flag these
> 'ghost' sessions."

### What good output looks like

For each proposed rule: the query (ES|QL/KQL/EQL), the fields used, a trigger
threshold/schedule, severity, and expected false positives. You'll typically
get rules that map onto anomalies #1–#6 above — that mapping is how you grade it.

---

## Step 4 — Validate the agent's rules against ground truth

Now the labels earn their keep. For any rule the agent proposes, compare what it
catches against `zpa.anomaly.flag`:

- **True positives** — events the rule fires on that have the matching
  `zpa.anomaly.flag`.
- **False positives** — events the rule fires on where
  `zpa.anomaly.is_anomalous` is `false`.
- **False negatives** — events with the target `zpa.anomaly.flag` the rule
  missed.

Example check in ES|QL — precision/recall for an over-privilege rule the agent
wrote (here its predicate is represented by `rule_match`):

```esql
FROM zpa-user-activity-logs
| WHERE @timestamp > NOW() - 1 hour
| EVAL is_truth = zpa.anomaly.flag == "OVER_PRIVILEGED"
| EVAL rule_match = /* the agent's predicate, e.g. */
       zpa.application_segment == "SEG-FINANCE-ERP" AND NOT user.roles IN ("finance_analyst","finance_manager","cfo","bss_manager","hr_manager","ciso")
| STATS tp = COUNT(*) WHERE rule_match AND is_truth,
        fp = COUNT(*) WHERE rule_match AND NOT is_truth,
        fn = COUNT(*) WHERE NOT rule_match AND is_truth
```

`precision = tp / (tp + fp)`, `recall = tp / (tp + fn)`. Iterate the agent's
rule until both are acceptable. Repeat per anomaly class.

---

## Creating labeled incidents on demand

To produce a clean, time-boxed burst of a specific anomaly (so the agent — or
your rule — has something unambiguous to catch), arm a scenario in
`zpa_scenarios.yaml` and save; it hot-reloads within ~10s. See the README's
[scenarios section](ZPA_STREAM_README.md#timed-anomaly-spikes-scenarios).

```bash
python zpa_stream_generator.py --list-scenarios   # preview the schedule
```

Useful patterns:

- **Reliable detection demo** — a `relative` spike of `over_privileged` to ~0.3
  for a few minutes gives the agent a dense, recent window to find.
- **Credential-stuffing rule test** — the `auth-failure-wave` `every` scenario
  produces recurring `ZPA_AUTH_FAILURE` bursts to validate a rate/threshold rule.
- **Quiet baseline** — keep all scenarios disabled and run only the low
  background anomaly rates from `zpa_rates.yaml` to test false-positive behaviour.

The console prints `▲ '<name>' spike STARTED` / `▼ ... ended` so you can line up
detections with the exact window.

---

## Tuning what's in the data

| Want | Where | How |
|---|---|---|
| More/less of an anomaly in the background | `zpa_rates.yaml` | raise/lower the `*_anomaly_rates` value |
| Overall traffic volume | `zpa_rates.yaml` | `event_rate.*_per_minute` |
| A new insider-threat actor | `zpa_users.yaml` | add a user with `behaviour.over_privileged: true` |
| A new dormant/ghost case | `zpa_users.yaml` / `zpa_log_config.yaml` | flag a user `ghost: true`, or mark a segment `dormant: true` |
| Anomalies tied to specific repeat offenders vs random noise | `zpa_rates.yaml` | `random_user_anomaly_share` (0 = always the flagged population) |
| Timed spikes | `zpa_scenarios.yaml` | arm a scenario |

All four runtime files (`zpa_users.yaml`, `zpa_rates.yaml`, `zpa_scenarios.yaml`)
hot-reload; `zpa_log_config.yaml` (topology + ES connection) is read once at
start.

---

## File map

| File | Role |
|---|---|
| `zpa_stream_generator.py` | The realtime streamer |
| `zpa_log_config.yaml` | Topology + Elasticsearch connection (the authz baseline lives here) |
| `zpa_users.yaml` | Synthetic user pool (flagged offenders) — hot-reloaded |
| `zpa_rates.yaml` | Event + anomaly rates — hot-reloaded |
| `zpa_scenarios.yaml` | Timed anomaly spikes — hot-reloaded |
| `es_templates/` | Component + index templates for the two data streams |
| `ZPA_STREAM_README.md` | Full operating manual for the streamer |
| `ZPA_DETECTION_LAB_GUIDE.md` | **This file** — the detection-engineering workflow |
