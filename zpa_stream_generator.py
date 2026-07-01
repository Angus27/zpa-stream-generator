#!/usr/bin/env python3
"""
zpa_stream_generator.py
───────────────────────
Realtime synthetic Zscaler Private Access (ZPA) log streamer.

Unlike the batch CSV generator (zpa_log_generator.py), this version emits events
continuously with live timestamps and bulk-indexes them into two Elasticsearch
data streams as ECS-mapped documents:

  • zpa-user-activity-logs  — per-connection records (segment, app, bytes, action)
  • zpa-user-status-logs    — session lifecycle events (auth, tunnel, posture, idle)

Most anomalies are produced by a flagged user population (behaviour flags in the
user pool file) so detection rules can catch repeat offenders; a small,
adjustable share is diverted to random users for unpredictable noise.

Three config files
  zpa_log_config.yaml   static topology + ES connection (segments, roles, ...)
  zpa_users.yaml        the synthetic user pool        — hot-reloaded
  zpa_rates.yaml        event rate + anomaly rates      — hot-reloaded (~10s)

Usage
  python zpa_stream_generator.py --init-users        # generate zpa_users.yaml
  python zpa_stream_generator.py --setup             # create templates + data streams
  python zpa_stream_generator.py --setup --recreate  # delete + recreate (DANGER: drops data)
  python zpa_stream_generator.py                     # start streaming
  python zpa_stream_generator.py --dry-run           # stream to stdout, do not send to ES

Requirements
  pip install pyyaml requests
"""

import argparse
import copy
import json
import os
import random
import re
import signal
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")


ECS_VERSION = "8.11.0"
TEMPLATE_DIR = Path(__file__).resolve().parent / "es_templates"


# ─── Config helpers ─────────────────────────────────────────────────────────

def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f) or {}

def cfg(conf, *keys, default=None):
    """Safe nested key lookup with a default."""
    node = conf
    for k in keys:
        if not isinstance(node, dict) or k not in node:
            return default
        node = node[k]
    return node


class HotFile:
    """A YAML file that is re-read when its mtime changes, throttled to a
    minimum interval. Lets the operator edit rates / users live."""

    def __init__(self, path, min_interval=10):
        self.path = Path(path)
        self.min_interval = min_interval
        self.data = {}
        self._mtime = None
        self._last_check = 0.0
        self.reload(force=True)

    def reload(self, force=False):
        now = time.monotonic()
        if not force and (now - self._last_check) < self.min_interval:
            return False
        self._last_check = now
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return False
        if not force and mtime == self._mtime:
            return False
        try:
            self.data = load_yaml(self.path)
            self._mtime = mtime
            return True
        except Exception as e:  # noqa: BLE001 — never let a bad edit kill the stream
            print(f"[warn] could not reload {self.path.name}: {e}", file=sys.stderr)
            return False


# ─── Scenarios: timed anomaly spikes ────────────────────────────────────────
# A scenario temporarily OVERRIDES rate/anomaly values from zpa_rates.yaml for a
# scheduled window, then reverts. Overlapping scenarios merge by taking the max
# value for each key.

_DUR_RE = re.compile(r"(\d+)\s*([smh])")

def parse_duration(val, default=0.0):
    """'90s' / '5m' / '1h' / '1h30m' / plain seconds -> float seconds."""
    if val is None:
        return float(default)
    if isinstance(val, (int, float)):
        return float(val)
    s = str(val).strip()
    if s.isdigit():
        return float(s)
    total, found = 0, False
    for n, u in _DUR_RE.findall(s):
        found = True
        total += int(n) * {"s": 1, "m": 60, "h": 3600}[u]
    return float(total) if found else float(default)


def _parse_at(s, wall):
    """Parse 'HH:MM[:SS]' (today, local) or an ISO datetime into a datetime."""
    if not s:
        return None
    s = str(s).strip()
    try:
        if "T" in s or "-" in s:
            return datetime.fromisoformat(s)
        parts = [int(x) for x in s.split(":")]
        h = parts[0]
        m = parts[1] if len(parts) > 1 else 0
        sec = parts[2] if len(parts) > 2 else 0
        return wall.replace(hour=h, minute=m, second=sec, microsecond=0)
    except Exception:  # noqa: BLE001
        return None


def scenario_active(sc, elapsed, wall):
    """Is this scenario's spike window open right now?
    elapsed = seconds since stream start (monotonic); wall = local datetime."""
    sch = sc.get("schedule", {}) or {}
    stype = sch.get("type", "relative")
    dur = parse_duration(sch.get("duration"), 60)
    if stype == "relative":
        start = parse_duration(sch.get("start"), 0)
        return start <= elapsed < start + dur
    if stype == "every":
        period = parse_duration(sch.get("period") or sch.get("start"), 0)
        offset = parse_duration(sch.get("offset"), 0)
        if period <= 0 or elapsed < offset:
            return False
        return ((elapsed - offset) % period) < dur
    if stype == "at":
        target = _parse_at(sch.get("start"), wall)
        if target is None:
            return False
        return target <= wall < target + timedelta(seconds=dur)
    return False


def merge_spike(base, override):
    """Deep-merge override into base in place; numeric leaves take the max."""
    for k, v in (override or {}).items():
        if isinstance(v, dict):
            node = base.setdefault(k, {})
            if isinstance(node, dict):
                merge_spike(node, v)
            else:
                base[k] = copy.deepcopy(v)
        else:
            cur = base.get(k)
            if isinstance(cur, (int, float)) and isinstance(v, (int, float)):
                base[k] = max(cur, v)
            else:
                base[k] = v
    return base


def compute_effective_rates(base, scenarios, elapsed, wall):
    """Return (effective_rates, active_scenario_names) for the current instant."""
    eff = copy.deepcopy(base) if base else {}
    active = []
    for sc in (scenarios or []):
        if not isinstance(sc, dict) or not sc.get("enabled", True):
            continue
        if scenario_active(sc, elapsed, wall):
            merge_spike(eff, sc.get("spikes", {}) or {})
            active.append(sc.get("name", "unnamed"))
    return eff, active


# ─── Small generators ─────────────────────────────────────────────────────────

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def rand_private_ip():
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def gen_session_id():
    return uuid.uuid4().hex[:16].upper()

def gen_event_id():
    return uuid.uuid4().hex[:12].upper()


# ─── User pool ──────────────────────────────────────────────────────────────

def build_user_pool(conf):
    """Generate an initial user pool dict suitable for writing to zpa_users.yaml.
    Used by --init-users; afterwards the file is the source of truth."""
    roles = cfg(conf, "roles", default={})
    first_names = cfg(conf, "user_names", "first",
                      default=["James", "Sarah", "Mohammed", "Priya", "Tom"])
    last_names = cfg(conf, "user_names", "last",
                     default=["Williams", "Patel", "Chen", "Hassan", "Jones"])
    domain = cfg(conf, "organisation", "internal_domain", default="corp.internal")
    user_count = cfg(conf, "dataset", "user_count", default=80)
    n_overpriv = cfg(conf, "dataset", "over_privileged_user_count", default=8)
    n_ghost = cfg(conf, "dataset", "ghost_user_count", default=4)
    role_keys = list(roles.keys()) or ["user"]

    users = []
    for i in range(user_count):
        fn = random.choice(first_names)
        ln = random.choice(last_names)
        role = random.choice(role_keys)
        dept = roles.get(role, {}).get("department", "Unknown")
        clean_ln = ln.lower().replace(" ", "").replace("'", "")
        username = f"{fn[0].lower()}{clean_ln}"
        users.append({
            "user_id": f"u{i+1:04d}",
            "username": username,
            "email": f"{username}@{domain}",
            "display": f"{fn} {ln}",
            "role": role,
            "department": dept,
            "behaviour": {"over_privileged": False, "ghost": False},
        })

    n_overpriv = min(n_overpriv, len(users))
    n_ghost = min(n_ghost, len(users) - n_overpriv)
    idx = list(range(len(users)))
    op_idx = set(random.sample(idx, n_overpriv))
    gh_idx = set(random.sample([i for i in idx if i not in op_idx], n_ghost))
    for i in op_idx:
        users[i]["behaviour"]["over_privileged"] = True
    for i in gh_idx:
        users[i]["behaviour"]["ghost"] = True
    return {"users": users}


def parse_users(users_data):
    """Split a loaded users file into role-keyed views used by the stream loop."""
    users = users_data.get("users", []) if isinstance(users_data, dict) else []
    active, over_priv, ghost = [], [], []
    by_role = {}
    for u in users:
        beh = u.get("behaviour", {}) or {}
        if beh.get("ghost"):
            ghost.append(u)
        else:
            active.append(u)
            by_role.setdefault(u.get("role"), []).append(u)
        if beh.get("over_privileged"):
            over_priv.append(u)
    return {
        "all": users,
        "active": active,        # non-ghost users that open application sessions
        "over_priv": over_priv,  # flagged over-privileged population
        "ghost": ghost,          # flagged ghost population
        "by_role": by_role,
    }


# ─── ECS document builders ────────────────────────────────────────────────────

def _app_host(seg_name, seg_cfg, domain, max_apps):
    prefix = seg_cfg.get("app_prefix", seg_name.lower())
    n = random.randint(1, max(1, max_apps))
    port = random.choice(seg_cfg.get("ports", [443]))
    return f"{prefix}-app{n:02d}.{domain}", port


def activity_doc(conf, user, seg_name, seg_cfg, connector_groups,
                 action="Allow", anomaly_flag="", anomaly_detail=""):
    domain = cfg(conf, "organisation", "internal_domain", default="corp.internal")
    max_apps = cfg(conf, "session", "apps_per_segment", default=6)
    cg = seg_cfg.get("connector_group", next(iter(connector_groups), "CG-DEFAULT"))
    cg_ips = connector_groups.get(cg, ["10.0.0.1"])
    connector_ip = random.choice(cg_ips)
    host, port = _app_host(seg_name, seg_cfg, domain, max_apps)

    denied = action == "Deny"
    dur = 0 if denied else random.randint(
        cfg(conf, "session", "duration_min_s", default=5),
        cfg(conf, "session", "duration_max_s", default=3600))
    btx = 0 if denied else random.randint(
        cfg(conf, "session", "bytes_tx_min", default=1024),
        cfg(conf, "session", "bytes_tx_max", default=5242880))
    brx = 0 if denied else random.randint(
        cfg(conf, "session", "bytes_rx_min", default=512),
        cfg(conf, "session", "bytes_rx_max", default=2097152))
    posture = "Fail" if random.random() < cfg(conf, "session", "posture_fail_rate", default=0.15) else "Pass"

    zpa = {
        "department": user.get("department", "Unknown"),
        "policy_action": action,
        "application_segment": seg_name,
        "app_host": host,
        "connector": {"group": cg, "ip": connector_ip},
        "idp": {"provider": cfg(conf, "organisation", "idp_provider", default="AzureAD")},
        "posture": {"check": posture},
        "session": {"id": gen_session_id(), "duration_seconds": dur},
        "anomaly": {"is_anomalous": bool(anomaly_flag)},
    }
    if anomaly_flag:
        zpa["anomaly"]["flag"] = anomaly_flag
        zpa["anomaly"]["detail"] = anomaly_detail

    return {
        "@timestamp": now_iso(),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": "event",
            "module": "zpa",
            "dataset": "zpa.activity",
            "category": ["network"],
            "type": ["access", "allowed" if not denied else "denied"],
            "action": "allow" if not denied else "deny",
            "outcome": "success" if not denied else "failure",
        },
        "user": {
            "id": user["user_id"],
            "name": user["username"],
            "email": user["email"],
            "roles": [user.get("role")] if user.get("role") else [],
            "domain": domain,
        },
        "source": {"ip": rand_private_ip(), "bytes": btx},
        "destination": {"domain": host, "port": port, "bytes": brx},
        "network": {"transport": "tcp", "protocol": "tcp", "bytes": btx + brx},
        "url": {"domain": host},
        "observer": {"name": cg, "ip": connector_ip, "type": "gateway", "vendor": "Zscaler"},
        "zpa": zpa,
    }


# event_type -> (ecs category, base outcome)
_STATUS_CATEGORY = {
    "ZPA_AUTH_SUCCESS": "authentication", "ZPA_AUTH_FAILURE": "authentication",
    "ZPA_IDP_TOKEN_REFRESH": "authentication", "ZPA_POSTURE_FAIL": "authentication",
}

def status_doc(conf, user, event_type, anomaly_flag="", status_detail="",
               session_duration=None):
    domain = cfg(conf, "organisation", "internal_domain", default="corp.internal")
    versions = cfg(conf, "client", "versions", default=["4.2.0"])
    platforms = cfg(conf, "client", "os_platforms", default=["Windows 11"])
    cgs = cfg(conf, "organisation", "connector_groups", default={})
    cg = random.choice(list(cgs)) if cgs else "CG-DEFAULT"
    failure = "FAILURE" in event_type or "FAIL" in event_type
    posture = "Fail" if "POSTURE_FAIL" in event_type else "Pass"
    category = _STATUS_CATEGORY.get(event_type, "session")

    zpa = {
        "department": user.get("department", "Unknown"),
        "cloud": cfg(conf, "organisation", "zpa_cloud", default="zpa.corp.net"),
        "event_type": event_type,
        "connector": {"group": cg},
        "idp": {"provider": cfg(conf, "organisation", "idp_provider", default="AzureAD"),
                "group": user.get("department", "Unknown")},
        "posture": {"status": posture},
        "client": {"version": random.choice(versions)},
        "anomaly": {"is_anomalous": bool(anomaly_flag)},
    }
    if session_duration is not None:
        zpa["session"] = {"duration_seconds": session_duration}
    if anomaly_flag:
        zpa["anomaly"]["flag"] = anomaly_flag
        zpa["anomaly"]["detail"] = status_detail

    doc = {
        "@timestamp": now_iso(),
        "ecs": {"version": ECS_VERSION},
        "message": status_detail or event_type,
        "event": {
            "kind": "event",
            "module": "zpa",
            "dataset": "zpa.status",
            "id": gen_event_id(),
            "category": [category],
            "type": ["info"],
            "action": event_type.lower(),
            "outcome": "failure" if failure else "success",
        },
        "user": {
            "id": user["user_id"],
            "name": user["username"],
            "email": user["email"],
            "roles": [user.get("role")] if user.get("role") else [],
            "domain": domain,
            "group": {"name": user.get("department", "Unknown")},
        },
        "source": {"ip": rand_private_ip()},
        "host": {"name": user["username"], "os": {"full": random.choice(platforms)}},
        "agent": {"name": "zpa-client", "version": zpa["client"]["version"]},
        "zpa": zpa,
    }
    return doc


# ─── Event selection (which event to emit, by whom) ─────────────────────────────

def pick(seq):
    return random.choice(seq) if seq else None


def make_activity_event(conf, users, rates, segments, connector_groups,
                        non_dormant, dormant_segs, cross_rules):
    """Decide the next activity event's type + actor and build the ECS doc."""
    ar = rates.get("activity_anomaly_rates", {}) or {}
    wildcard = float(rates.get("random_user_anomaly_share", 0.0) or 0.0)
    roll = random.random()

    # --- Over-privileged ---------------------------------------------------
    cum = ar.get("over_privileged", 0.0)
    if roll < cum:
        # flagged population by default; occasionally a random non-flagged user
        if users["over_priv"] and random.random() >= wildcard:
            user = pick(users["over_priv"])
        else:
            user = pick(users["active"]) or pick(users["all"])
        if not user:
            return None
        role_segs = cfg(conf, "roles", user.get("role"), "primary_segs", default=[])
        foreign = [s for s in non_dormant if s not in role_segs]
        seg = pick(foreign)
        if not seg:
            return None
        return ("activity", activity_doc(
            conf, user, seg, segments[seg], connector_groups,
            anomaly_flag="OVER_PRIVILEGED",
            anomaly_detail=f"Role '{user.get('role')}' not in authorised_roles for {seg}"))

    # --- Cross-segment (role-driven) ---------------------------------------
    cum += ar.get("cross_segment", 0.0)
    if roll < cum and cross_rules:
        rule = pick(cross_rules)
        seg = rule.get("segment")
        if seg in segments:
            trole = pick(rule.get("unexpected_roles", []))
            candidates = users["by_role"].get(trole, [])
            user = pick(candidates) or pick(users["active"])
            if user:
                return ("activity", activity_doc(
                    conf, user, seg, segments[seg], connector_groups,
                    anomaly_flag="CROSS_SEGMENT",
                    anomaly_detail=(f"Unexpected: {user.get('department')} user "
                                    f"({user.get('role')}) accessed {seg}")))

    # --- Dormant segment ---------------------------------------------------
    cum += ar.get("dormant_segment", 0.0)
    if roll < cum and dormant_segs:
        seg = pick(dormant_segs)
        user = pick(users["all"])
        if user:
            return ("activity", activity_doc(
                conf, user, seg, segments[seg], connector_groups,
                anomaly_flag="DORMANT_SEGMENT",
                anomaly_detail=f"{seg} is dormant; policy not reviewed in >90 days"))

    # --- Access denied -----------------------------------------------------
    cum += ar.get("access_denied", 0.0)
    if roll < cum:
        user = pick(users["all"])
        if user:
            role_segs = cfg(conf, "roles", user.get("role"), "primary_segs", default=[])
            foreign = [s for s in non_dormant if s not in role_segs]
            seg = pick(foreign)
            if seg:
                return ("activity", activity_doc(
                    conf, user, seg, segments[seg], connector_groups,
                    action="Deny", anomaly_flag="ACCESS_DENIED",
                    anomaly_detail=f"Policy deny: {user.get('role')} attempted access to {seg}"))

    # --- Normal authorised traffic ----------------------------------------
    user = pick(users["active"])
    if not user:
        return None
    role_segs = cfg(conf, "roles", user.get("role"), "primary_segs", default=[])
    eligible = [s for s in role_segs
                if s in segments and not segments[s].get("dormant", False)]
    if not eligible:
        eligible = [s for s, v in segments.items()
                    if "all" in v.get("authorised_roles", []) and not v.get("dormant", False)]
    seg = pick(eligible)
    if not seg:
        return None
    return ("activity", activity_doc(conf, user, seg, segments[seg], connector_groups))


def make_status_event(conf, users, rates):
    sr = rates.get("status_anomaly_rates", {}) or {}
    wildcard = float(rates.get("random_user_anomaly_share", 0.0) or 0.0)
    roll = random.random()

    cum = sr.get("ghost_user", 0.0)
    if roll < cum:
        if users["ghost"] and random.random() >= wildcard:
            user = pick(users["ghost"])
        else:
            user = pick(users["active"]) or pick(users["all"])
        if user:
            event = pick(["ZPA_CLIENT_CONNECTED", "ZPA_AUTH_SUCCESS", "ZPA_IDP_TOKEN_REFRESH"])
            return ("status", status_doc(
                conf, user, event, anomaly_flag="GHOST_USER",
                status_detail="Authenticated but initiated no application sessions"))

    cum += sr.get("auth_failure", 0.0)
    if roll < cum:
        user = pick(users["active"]) or pick(users["all"])
        if user:
            return ("status", status_doc(
                conf, user, "ZPA_AUTH_FAILURE",
                status_detail="IdP authentication failed"))

    cum += sr.get("posture_fail", 0.0)
    if roll < cum:
        user = pick(users["active"]) or pick(users["all"])
        if user:
            return ("status", status_doc(
                conf, user, "ZPA_POSTURE_FAIL",
                status_detail="Device posture check failed"))

    # Normal lifecycle event, weighted per static config
    user = pick(users["active"]) or pick(users["all"])
    if not user:
        return None
    event_types = cfg(conf, "client", "status_event_types", default=["ZPA_AUTH_SUCCESS"])
    weights = cfg(conf, "client", "status_event_weights", default=None)
    event = (random.choices(event_types, weights=weights)[0] if weights
             else random.choice(event_types))
    dur = (random.randint(60, 28800)
           if any(x in event for x in ["DISCONNECTED", "TIMEOUT"]) else None)
    return ("status", status_doc(conf, user, event, session_duration=dur))


# ─── Elasticsearch client (requests + _bulk, ApiKey auth) ───────────────────────

class ESClient:
    def __init__(self, conf):
        try:
            import requests  # lazy import: --init-users / --dry-run need no ES
        except ImportError:
            sys.exit("requests is required for Elasticsearch I/O: pip install requests")
        self.requests = requests
        self.endpoint = (os.environ.get("ELASTIC_ENDPOINT")
                         or cfg(conf, "elasticsearch", "endpoint", default="https://localhost:9200")).rstrip("/")
        api_key = os.environ.get("ELASTIC_API_KEY") or cfg(conf, "elasticsearch", "api_key")
        if not api_key:
            sys.exit("No API key. Set ELASTIC_API_KEY or elasticsearch.api_key in the config.")
        self.timeout = cfg(conf, "elasticsearch", "request_timeout_seconds", default=30)
        ca = cfg(conf, "elasticsearch", "ca_certs")
        verify = cfg(conf, "elasticsearch", "verify_certs", default=True)
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"ApiKey {api_key}",
            "Content-Type": "application/json",
        })
        self.session.verify = ca if ca else verify
        if verify is False:
            try:
                from urllib3.exceptions import InsecureRequestWarning
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # noqa
            except Exception:  # noqa: BLE001
                pass

    def _req(self, method, path, body=None, ndjson=False):
        url = f"{self.endpoint}{path}"
        if ndjson:
            data = body
            headers = {"Content-Type": "application/x-ndjson"}
        else:
            data = json.dumps(body) if body is not None else None
            headers = None
        resp = self.session.request(method, url, data=data, headers=headers, timeout=self.timeout)
        return resp

    def ping(self):
        r = self._req("GET", "/")
        r.raise_for_status()
        info = r.json()
        ver = cfg(info, "version", "number", default="?")
        print(f"[es] connected to {self.endpoint}  (version {ver})")

    def put_component_template(self, name, body):
        r = self._req("PUT", f"/_component_template/{name}", body)
        r.raise_for_status()
        print(f"[es] component_template '{name}' applied")

    def put_index_template(self, name, body):
        r = self._req("PUT", f"/_index_template/{name}", body)
        r.raise_for_status()
        print(f"[es] index_template '{name}' applied")

    def datastream_exists(self, name):
        return self._req("GET", f"/_data_stream/{name}").status_code == 200

    def create_datastream(self, name):
        if self.datastream_exists(name):
            print(f"[es] data_stream '{name}' already exists")
            return
        r = self._req("PUT", f"/_data_stream/{name}")
        r.raise_for_status()
        print(f"[es] data_stream '{name}' created")

    def delete_datastream(self, name):
        r = self._req("DELETE", f"/_data_stream/{name}")
        if r.status_code in (200, 404):
            print(f"[es] data_stream '{name}' deleted")
        else:
            r.raise_for_status()

    def bulk(self, datastream, docs):
        """Bulk-create docs into a data stream. Returns (indexed, errors)."""
        if not docs:
            return 0, 0
        lines = []
        action = json.dumps({"create": {"_index": datastream}})
        for d in docs:
            lines.append(action)
            lines.append(json.dumps(d))
        payload = "\n".join(lines) + "\n"
        r = self._req("POST", "/_bulk", payload, ndjson=True)
        r.raise_for_status()
        body = r.json()
        if not body.get("errors"):
            return len(docs), 0
        errs = 0
        first = None
        for item in body.get("items", []):
            res = next(iter(item.values()))
            if res.get("error"):
                errs += 1
                if first is None:
                    first = res["error"]
        if first:
            print(f"[warn] {errs}/{len(docs)} docs rejected by '{datastream}': "
                  f"{first.get('type')}: {first.get('reason')}", file=sys.stderr)
        return len(docs) - errs, errs


# ─── Setup: templates + data streams ────────────────────────────────────────────

def run_setup(conf, recreate=False):
    es = ESClient(conf)
    es.ping()
    activity_ds = cfg(conf, "elasticsearch", "datastreams", "activity", default="zpa-user-activity-logs")
    status_ds = cfg(conf, "elasticsearch", "datastreams", "status", default="zpa-user-status-logs")

    if recreate:
        es.delete_datastream(activity_ds)
        es.delete_datastream(status_ds)

    def load_tpl(fname):
        with open(TEMPLATE_DIR / fname) as f:
            return json.load(f)

    es.put_component_template("zpa-common-settings", load_tpl("component-zpa-common-settings.json"))
    es.put_component_template("zpa-activity-mappings", load_tpl("component-zpa-activity-mappings.json"))
    es.put_component_template("zpa-status-mappings", load_tpl("component-zpa-status-mappings.json"))
    es.put_index_template("zpa-user-activity-logs", load_tpl("index-template-zpa-user-activity-logs.json"))
    es.put_index_template("zpa-user-status-logs", load_tpl("index-template-zpa-user-status-logs.json"))
    es.create_datastream(activity_ds)
    es.create_datastream(status_ds)
    print("\n[setup] complete — data streams are ready to receive events.")


# ─── Streaming loop ─────────────────────────────────────────────────────────

class Streamer:
    def __init__(self, conf, dry_run=False, include_anomaly_fields=None):
        self.conf = conf
        self.dry_run = dry_run
        # answer-key labels (zpa.anomaly.*) are included by default; disable for
        # blind detection-engineering runs. CLI override wins over config.
        self.include_anomaly_fields = (
            cfg(conf, "streaming", "include_anomaly_fields", default=True)
            if include_anomaly_fields is None else include_anomaly_fields)
        interval = cfg(conf, "streaming", "reload_interval_seconds", default=10)
        rates_file = cfg(conf, "streaming", "rates_file", default="zpa_rates.yaml")
        users_file = cfg(conf, "streaming", "users_file", default="zpa_users.yaml")
        scenarios_file = cfg(conf, "streaming", "scenarios_file", default="zpa_scenarios.yaml")
        self.rates = HotFile(rates_file, min_interval=interval)
        self.users_file = HotFile(users_file, min_interval=interval)
        self.scenarios = HotFile(scenarios_file, min_interval=interval)
        if not self.users_file.data.get("users"):
            sys.exit(f"No users in {users_file}. Run: python {Path(__file__).name} --init-users")
        self.users = parse_users(self.users_file.data)

        # effective rates = base rates with any active scenario spikes merged in
        self.eff_rates = self.rates.data
        self.active_scenarios = set()
        self.start_mono = time.monotonic()

        # static topology snapshot
        self.segments = cfg(conf, "segments", default={})
        self.connector_groups = cfg(conf, "organisation", "connector_groups", default={})
        self.cross_rules = cfg(conf, "cross_segment_rules", default=[])
        self.non_dormant = [s for s, v in self.segments.items() if not v.get("dormant", False)]
        self.dormant_segs = [s for s, v in self.segments.items() if v.get("dormant", False)]

        self.activity_ds = cfg(conf, "elasticsearch", "datastreams", "activity", default="zpa-user-activity-logs")
        self.status_ds = cfg(conf, "elasticsearch", "datastreams", "status", default="zpa-user-status-logs")
        self.bulk_max = cfg(conf, "elasticsearch", "bulk_max_docs", default=500)
        self.flush_interval = cfg(conf, "elasticsearch", "flush_interval_seconds", default=2)

        self.es = None if dry_run else ESClient(conf)
        if self.es:
            self.es.ping()

        self.buf_activity = []
        self.buf_status = []
        self.sent = {"activity": 0, "status": 0}
        self.errors = 0
        self.running = True

    # -- rate accessors (live, post-scenario) --
    def _rate_per_sec(self, key):
        per_min = cfg(self.eff_rates, "event_rate", key, default=0)
        return max(0.0, float(per_min) / 60.0)

    def apply_scenarios(self, now):
        """Recompute effective rates from base rates + active spike windows,
        and log spike start/end transitions."""
        elapsed = now - self.start_mono
        wall = datetime.now()
        scenarios = cfg(self.scenarios.data, "scenarios", default=[])
        self.eff_rates, active = compute_effective_rates(
            self.rates.data, scenarios, elapsed, wall)
        new = set(active)
        for name in sorted(new - self.active_scenarios):
            print(f"[scenario] ▲ '{name}' spike STARTED")
        for name in sorted(self.active_scenarios - new):
            print(f"[scenario] ▼ '{name}' spike ended")
        self.active_scenarios = new

    def reload(self):
        if self.users_file.reload() and self.users_file.data.get("users"):
            self.users = parse_users(self.users_file.data)
            print(f"[reload] user pool: {len(self.users['all'])} users "
                  f"({len(self.users['over_priv'])} over-priv, {len(self.users['ghost'])} ghost)")
        if self.rates.reload():
            ev = self.rates.data.get("event_rate", {})
            print(f"[reload] rates: activity={ev.get('activity_per_minute')}/min "
                  f"status={ev.get('status_per_minute')}/min")
        if self.scenarios.reload():
            scs = cfg(self.scenarios.data, "scenarios", default=[]) or []
            armed = [s.get("name") for s in scs if isinstance(s, dict) and s.get("enabled", True)]
            print(f"[reload] scenarios: {len(scs)} defined, {len(armed)} armed "
                  f"({', '.join(armed) or 'none'})")

    def emit_one(self, stream):
        rates = self.eff_rates
        if stream == "activity":
            evt = make_activity_event(self.conf, self.users, rates, self.segments,
                                      self.connector_groups, self.non_dormant,
                                      self.dormant_segs, self.cross_rules)
        else:
            evt = make_status_event(self.conf, self.users, rates)
        if not evt:
            return
        kind, doc = evt
        flag = cfg(doc, "zpa", "anomaly", "flag", default="-")
        if not self.include_anomaly_fields and isinstance(doc.get("zpa"), dict):
            doc["zpa"].pop("anomaly", None)        # drop the answer key for blind runs
        if self.dry_run:
            print(f"  [{kind:8s}] {doc['@timestamp']} {doc['user']['name']:14s} {flag}")
            self.sent[kind] += 1
            return
        (self.buf_activity if kind == "activity" else self.buf_status).append(doc)

    def flush(self):
        if self.es is None:
            return
        for ds, buf, key in ((self.activity_ds, self.buf_activity, "activity"),
                             (self.status_ds, self.buf_status, "status")):
            if not buf:
                continue
            for attempt in range(4):
                try:
                    ok, err = self.es.bulk(ds, buf)
                    self.sent[key] += ok
                    self.errors += err
                    buf.clear()
                    break
                except (self.es.requests.exceptions.ReadTimeout,
                        self.es.requests.exceptions.ConnectionError) as exc:
                    wait = 5 * (2 ** attempt)
                    print(f"[warn] bulk to '{ds}' failed ({exc.__class__.__name__}), "
                          f"retry {attempt + 1}/3 in {wait}s", file=sys.stderr)
                    time.sleep(wait)
            else:
                print(f"[error] bulk to '{ds}' failed after 3 retries — dropping "
                      f"{len(buf)} docs", file=sys.stderr)
                self.errors += len(buf)
                buf.clear()

    def run(self):
        armed = [s.get("name") for s in (cfg(self.scenarios.data, "scenarios", default=[]) or [])
                 if isinstance(s, dict) and s.get("enabled", True)]
        print(f"[stream] started{' (DRY RUN)' if self.dry_run else ''} — Ctrl-C to stop")
        if not self.include_anomaly_fields:
            print("[stream] BLIND mode — zpa.anomaly.* answer-key fields are NOT being sent")
        if armed:
            print(f"[stream] {len(armed)} scenario(s) armed: {', '.join(armed)}")
        self.start_mono = time.monotonic()
        next_activity = self.start_mono
        next_status = self.start_mono
        last_flush = self.start_mono
        last_report = self.start_mono
        while self.running:
            now = time.monotonic()
            self.reload()
            self.apply_scenarios(now)

            ra = self._rate_per_sec("activity_per_minute")
            rs = self._rate_per_sec("status_per_minute")

            while ra > 0 and now >= next_activity:
                self.emit_one("activity")
                next_activity += random.expovariate(ra)
            if ra <= 0:
                next_activity = now + 1.0

            while rs > 0 and now >= next_status:
                self.emit_one("status")
                next_status += random.expovariate(rs)
            if rs <= 0:
                next_status = now + 1.0

            buffered = len(self.buf_activity) + len(self.buf_status)
            if buffered >= self.bulk_max or (buffered and now - last_flush >= self.flush_interval):
                self.flush()
                last_flush = now

            if now - last_report >= 15:
                spikes = (f" spikes=[{', '.join(sorted(self.active_scenarios))}]"
                          if self.active_scenarios else "")
                print(f"[stream] sent activity={self.sent['activity']} "
                      f"status={self.sent['status']} errors={self.errors}{spikes}")
                last_report = now

            time.sleep(0.05)

        self.flush()
        print(f"\n[stream] stopped. total activity={self.sent['activity']} "
              f"status={self.sent['status']} errors={self.errors}")

    def stop(self, *_):
        self.running = False


# ─── --init-users ─────────────────────────────────────────────────────────────

def run_init_users(conf, path, force=False):
    if os.path.exists(path) and not force:
        sys.exit(f"{path} already exists. Use --force to overwrite.")
    seed = cfg(conf, "dataset", "random_seed")
    if seed is not None:
        random.seed(int(seed))
    pool = build_user_pool(conf)
    header = (
        "# ─────────────────────────────────────────────────────────────────────\n"
        "# ZPA synthetic user pool — HOT-RELOADED while streaming.\n"
        "# Add or remove users any time; changes take effect within\n"
        "# streaming.reload_interval_seconds (default 10s). No restart needed.\n"
        "#\n"
        "# behaviour flags:\n"
        "#   over_privileged: occasionally accesses segments outside their role\n"
        "#                    (primary source of OVER_PRIVILEGED anomalies)\n"
        "#   ghost:           authenticates but never opens application sessions\n"
        "#                    (primary source of GHOST_USER anomalies)\n"
        "# ─────────────────────────────────────────────────────────────────────\n"
    )
    with open(path, "w") as f:
        f.write(header)
        yaml.safe_dump(pool, f, sort_keys=False, default_flow_style=False, width=120)
    n_op = sum(1 for u in pool["users"] if u["behaviour"]["over_privileged"])
    n_gh = sum(1 for u in pool["users"] if u["behaviour"]["ghost"])
    print(f"[init-users] wrote {len(pool['users'])} users to {path} "
          f"({n_op} over-privileged, {n_gh} ghost)")


# ─── --list-scenarios ──────────────────────────────────────────────────────────

def run_list_scenarios(conf):
    path = cfg(conf, "streaming", "scenarios_file", default="zpa_scenarios.yaml")
    if not os.path.exists(path):
        print(f"No scenarios file at {path}.")
        return
    scs = cfg(load_yaml(path), "scenarios", default=[]) or []
    if not scs:
        print(f"{path}: no scenarios defined.")
        return
    print(f"{path}: {len(scs)} scenario(s)\n")
    for sc in scs:
        if not isinstance(sc, dict):
            continue
        sch = sc.get("schedule", {}) or {}
        state = "ARMED " if sc.get("enabled", True) else "off   "
        stype = sch.get("type", "relative")
        if stype == "relative":
            when = f"{sch.get('start', 0)} after start, for {sch.get('duration')}"
        elif stype == "every":
            when = (f"every {sch.get('period') or sch.get('start')} for {sch.get('duration')}"
                    f"{' (offset ' + str(sch.get('offset')) + ')' if sch.get('offset') else ''}")
        elif stype == "at":
            when = f"at {sch.get('start')} for {sch.get('duration')}"
        else:
            when = "(unknown schedule)"
        print(f"  [{state}] {sc.get('name', 'unnamed'):24s} {stype:8s} {when}")
        for grp, vals in (sc.get("spikes", {}) or {}).items():
            if isinstance(vals, dict):
                inner = ", ".join(f"{k}={v}" for k, v in vals.items())
                print(f"             ↳ {grp}: {inner}")
            else:
                print(f"             ↳ {grp}={vals}")
    print()


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Realtime ZPA log streamer for Elasticsearch.")
    p.add_argument("--config", default="zpa_log_config.yaml", help="Static config (topology + ES connection)")
    p.add_argument("--setup", action="store_true", help="Create component/index templates and data streams, then exit")
    p.add_argument("--recreate", action="store_true", help="With --setup: delete the data streams first (DROPS DATA)")
    p.add_argument("--init-users", action="store_true", help="Generate the user pool file, then exit")
    p.add_argument("--force", action="store_true", help="With --init-users: overwrite an existing pool file")
    p.add_argument("--list-scenarios", action="store_true", help="Print the configured spike scenarios, then exit")
    p.add_argument("--no-anomaly-labels", action="store_true",
                   help="BLIND run: omit the zpa.anomaly.* answer-key fields from indexed docs "
                        "(overrides streaming.include_anomaly_fields)")
    p.add_argument("--dry-run", action="store_true", help="Stream to stdout instead of Elasticsearch")
    args = p.parse_args()

    if not os.path.exists(args.config):
        sys.exit(f"Config file not found: {args.config}")
    conf = load_yaml(args.config)

    if args.list_scenarios:
        run_list_scenarios(conf)
        return

    if args.init_users:
        users_file = cfg(conf, "streaming", "users_file", default="zpa_users.yaml")
        run_init_users(conf, users_file, force=args.force)
        return

    if args.setup:
        run_setup(conf, recreate=args.recreate)
        return

    streamer = Streamer(conf, dry_run=args.dry_run,
                        include_anomaly_fields=False if args.no_anomaly_labels else None)
    signal.signal(signal.SIGINT, streamer.stop)
    signal.signal(signal.SIGTERM, streamer.stop)
    streamer.run()


if __name__ == "__main__":
    main()
