# ZPA stream generator — realtime streaming to Elasticsearch

Use this utility as the basis for Agentic Analyis of ZPA logs, for example to report on segmentation health and create dashboards in Kibana agentically. This is a great datafeed for demos where you need ZScaler logs.

`zpa_stream_generator.py` emits synthetic Zscaler Private Access (ZPA) events
**continuously, with live timestamps**, and bulk-indexes them into two
Elasticsearch **data streams** as ECS-mapped documents.

| Data stream | Contents |
|---|---|
| `zpa-user-activity-logs` | per-connection records (segment, app, bytes, policy action) |
| `zpa-user-status-logs` | session lifecycle events (auth, tunnel, posture, idle) |

Also see the ZPA_DETECTION_LAB_GUIDE.md for real-world Agent Builder use cases.

---

## How it works

- Events arrive as a **Poisson process** — `zpa_rates.yaml` sets the *average*
  events/minute per stream; inter-arrival times are drawn from an exponential
  distribution, so traffic looks naturally bursty.
- Most anomalies come from a **flagged user population** (`zpa_users.yaml`) so a
  detection rule can catch a repeat offender. A small, tunable
  `random_user_anomaly_share` diverts some anomalies to random users for noise.
- **`zpa_rates.yaml` and `zpa_users.yaml` are hot-reloaded** (default every 10s).
  Edit a rate, add/remove a user, save — the change takes effect within seconds,
  no restart.
- Documents are **ECS-mapped** (`user.*`, `source.ip`, `destination.port`,
  `event.action`, etc.) with a `zpa.*` namespace for product-specific fields.
- Authentication is **API key** only (`Authorization: ApiKey …`).

---

## The config files

| File | Changes | Reloaded live? |
|---|---|---|
| `zpa_log_config.yaml` | Static topology (segments, roles, connectors, cross-segment rules) **+ Elasticsearch connection** | No — read once at start |
| `zpa_users.yaml` | The synthetic user pool. Add/remove users over time | **Yes** |
| `zpa_rates.yaml` | Overall event rate + per-anomaly rates | **Yes** |
| `zpa_scenarios.yaml` | Timed anomaly-spike scenarios | **Yes** |

---

## Requirements

Python 3.9+.

```bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install pyyaml requests
```

Activate the venv (`source venv/bin/activate`) in every new shell before running
`zpa_stream_generator.py`.

---

## Quick start

### 1. Set the Elasticsearch connection

Edit the `elasticsearch:` section of `zpa_log_config.yaml` (endpoint, TLS), then
provide the API key via environment variable (preferred — keeps it out of the file):

```bash
export ELASTIC_ENDPOINT="https://my-cluster:9200"
export ELASTIC_API_KEY="<base64 id:api_key from Kibana>"
```

> The API key is the **encoded** value Kibana shows under
> *Stack Management → API keys → Create*, or the `encoded` field returned by
> `POST /_security/api_key`. The key needs privileges to manage templates/data
> streams (for `--setup`) and to write to the two data streams.
> For a self-signed dev cluster, set `verify_certs: false` in the config.

### 2. Generate the user pool (once)

```bash
python zpa_stream_generator.py --init-users
```

Writes `zpa_users.yaml` (80 users, some flagged over-privileged / ghost). Edit it
freely afterwards — it is the source of truth from then on. Re-run with `--force`
to regenerate.

### 3. Create the templates and data streams (once)

```bash
python zpa_stream_generator.py --setup
```

This applies the three component templates and two index templates from
`es_templates/`, then creates both data streams. To wipe and start over
(**drops all indexed data**):

```bash
python zpa_stream_generator.py --setup --recreate
```

### 4. Stream

```bash
python zpa_stream_generator.py            # stream to Elasticsearch
python zpa_stream_generator.py --dry-run  # print events to stdout, send nothing
```

Stop with `Ctrl-C` — the buffer is flushed on shutdown.

---

## Tuning rates live

While the streamer runs, edit `zpa_rates.yaml` and save. Within
`reload_interval_seconds` you'll see a `[reload]` line and the new rates take
effect. Useful moves:

- **Trip a detection rule on demand** — bump an anomaly rate (e.g.
  `over_privileged: 0.20`) for a minute, then drop it back.
- **Pause a stream** — set its `*_per_minute` to `0`.
- **More/less repeat-offender behaviour** — lower/raise
  `random_user_anomaly_share` (0 = anomalies only from flagged users).

```yaml
event_rate:
  activity_per_minute: 120
  status_per_minute:    30
activity_anomaly_rates:
  over_privileged:  0.020
  cross_segment:    0.010
  dormant_segment:  0.004
  access_denied:    0.015
status_anomaly_rates:
  ghost_user:   0.010
  auth_failure: 0.020
  posture_fail: 0.030
random_user_anomaly_share: 0.05
```

---

## Timed anomaly spikes (scenarios)

For spikes that fire on a **schedule** rather than a steady background rate, use
`zpa_scenarios.yaml`. Each scenario temporarily **overrides** values from
`zpa_rates.yaml` for a scheduled window, then automatically reverts — ideal for
reliably tripping a detection rule at a known time, or for a scripted demo.

Preview the configured schedule without streaming:

```bash
python zpa_stream_generator.py --list-scenarios
```

Three schedule types:

| `schedule.type` | Fires | Keys |
|---|---|---|
| `relative` | an offset after the stream starts | `start`, `duration` |
| `every` | recurring window | `period`, `duration`, `offset` |
| `at` | a wall-clock time (local), today | `start` (`"HH:MM"` or ISO), `duration` |

Durations/offsets accept `90s`, `5m`, `1h`, `1h30m`, or a plain number of seconds.

```yaml
scenarios:
  - name: insider-threat-burst
    enabled: true                  # set true to arm; flip false to disable
    schedule:
      type: relative
      start: 2m                    # 2 minutes after the stream starts
      duration: 3m
    spikes:                        # any subset of the zpa_rates.yaml structure
      activity_anomaly_rates:
        over_privileged: 0.35
        cross_segment:   0.20
      random_user_anomaly_share: 0.0

  - name: auth-failure-wave
    enabled: true
    schedule:
      type: every
      period: 10m                  # every 10 minutes...
      duration: 60s                # ...for 60 seconds
    spikes:
      status_anomaly_rates:
        auth_failure: 0.40
```

Behaviour:

- `spikes` may set anything from `zpa_rates.yaml` — `event_rate` (volume),
  `activity_anomaly_rates`, `status_anomaly_rates`, `random_user_anomaly_share`.
  Anything not mentioned keeps its base value.
- When windows **overlap**, the **higher** value wins for each key.
- The file is hot-reloaded, so you can arm/disarm or retime scenarios live.
- The console logs `▲ '<name>' spike STARTED` / `▼ '<name>' spike ended`, and the
  periodic status line shows `spikes=[...]` while any are active.

Shipped disabled by default — flip `enabled: true` on the ones you want.

---

## Adding / removing users live

Edit `zpa_users.yaml` and save. Each user:

```yaml
- user_id: u0081
  username: jdoe
  email: jdoe@telco-corp.internal
  display: Jane Doe
  role: finance_analyst          # must match a role in zpa_log_config.yaml
  department: Finance
  behaviour:
    over_privileged: true        # primary source of OVER_PRIVILEGED anomalies
    ghost: false                 # true => authenticates but opens no sessions
```

- Remove a user → they stop generating events on the next reload.
- Add a user with `over_privileged: true` → introduce a new insider-threat actor.
- `ghost: true` users only appear in the status stream (auth/token, never sessions).

---

## Anomalies and ECS fields they touch

| Anomaly | Stream | Key fields for detection |
|---|---|---|
| `OVER_PRIVILEGED` | activity | `zpa.anomaly.flag`, `user.name`, `zpa.application_segment`, `user.roles` |
| `CROSS_SEGMENT` | activity | `zpa.anomaly.flag`, `user.roles`, `zpa.application_segment` |
| `DORMANT_SEGMENT` | activity | `zpa.anomaly.flag`, `zpa.application_segment` |
| `ACCESS_DENIED` | activity | `event.action: deny`, `event.outcome: failure`, `zpa.anomaly.flag` |
| `GHOST_USER` | status | `zpa.anomaly.flag`, `user.name`, absence of activity events |
| `auth_failure` | status | `event.action: zpa_auth_failure`, `event.outcome: failure` |
| `posture_fail` | status | `zpa.posture.status: Fail`, `event.action: zpa_posture_fail` |

Every anomalous doc also carries `zpa.anomaly.is_anomalous: true` and a
human-readable `zpa.anomaly.detail`.

---

## Elasticsearch artifacts (`es_templates/`)

`--setup` applies these for you, but the raw JSON is provided for review or for
pasting into **Kibana → Dev Tools**:

| File | Applied as |
|---|---|
| `component-zpa-common-settings.json` | `PUT _component_template/zpa-common-settings` |
| `component-zpa-activity-mappings.json` | `PUT _component_template/zpa-activity-mappings` |
| `component-zpa-status-mappings.json` | `PUT _component_template/zpa-status-mappings` |
| `index-template-zpa-user-activity-logs.json` | `PUT _index_template/zpa-user-activity-logs` |
| `index-template-zpa-user-status-logs.json` | `PUT _index_template/zpa-user-status-logs` |

Each index template sets `"data_stream": {}` and `composed_of` the common
settings plus its stream-specific mappings. After the templates exist, the data
streams are created with:

```
PUT _data_stream/zpa-user-activity-logs
PUT _data_stream/zpa-user-status-logs
```

Manual Dev Tools sequence (order matters — components before index templates):

```
PUT _component_template/zpa-common-settings
{ ...contents of component-zpa-common-settings.json... }

PUT _component_template/zpa-activity-mappings
{ ...contents of component-zpa-activity-mappings.json... }

PUT _component_template/zpa-status-mappings
{ ...contents of component-zpa-status-mappings.json... }

PUT _index_template/zpa-user-activity-logs
{ ...contents of index-template-zpa-user-activity-logs.json... }

PUT _index_template/zpa-user-status-logs
{ ...contents of index-template-zpa-user-status-logs.json... }

PUT _data_stream/zpa-user-activity-logs
PUT _data_stream/zpa-user-status-logs
```

---

## CLI reference

| Command | Effect |
|---|---|
| `--init-users` | Generate `zpa_users.yaml` from the topology, then exit |
| `--init-users --force` | Overwrite an existing pool file |
| `--list-scenarios` | Print the configured spike scenarios, then exit |
| `--setup` | Apply templates + create data streams, then exit |
| `--setup --recreate` | Delete the data streams first (**drops data**), then recreate |
| `--no-anomaly-labels` | **Blind run** — omit the `zpa.anomaly.*` answer-key fields from indexed docs (overrides `streaming.include_anomaly_fields`) |
| `--dry-run` | Stream to stdout instead of Elasticsearch (no ES connection needed) |
| `--config PATH` | Use a different static config file (default `zpa_log_config.yaml`) |
| *(no flag)* | Start streaming to Elasticsearch |
