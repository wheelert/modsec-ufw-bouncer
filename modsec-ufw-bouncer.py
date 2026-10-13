#!/usr/bin/python3
"""Read ModSecurity logs and manage temporary UFW denies by rule ID."""
from __future__ import annotations

import argparse
import configparser
import copy
import datetime as dt
import ipaddress
import json
import logging
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Set, Tuple

LOG = logging.getLogger("modsec-ufw-bouncer")
LINE_LIMIT = 4 * 1024 * 1024
AUDIT_HEADER = re.compile(r"^--+(?:[^-\s]+)?-(?P<section>[A-Z])--\s*(?P<body>.*)$")
CLIENT_RE = re.compile(r"""\[client(?:[-_ ]?ip)?[:=]?\s+"?(?P<ip>[0-9A-Fa-f:.]+)"?\]""", re.IGNORECASE)
RULE_ID_RE = re.compile(r"""\[id\s+(?:"(?P<q1>[^"]+)"|'(?P<q2>[^']+)'|(?P<bare>[0-9A-Za-z_-]+))\s*\]""")
UNIQUE_RE = re.compile(r"""\[unique(?:_id)?\s+(?:"(?P<q1>[^"]+)"|'(?P<q2>[^']+)'|(?P<bare>[0-9A-Za-z_.-]+))\s*\]""", re.IGNORECASE)
TIMESTAMP_RE = re.compile(r"(?:\[)?(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}(?::\d{2}){3}(?:\s+[+-]\d{4})?)(?:\])?(?:\s+(?P<body>.*)|$)")
ISO_KEYS = ("timestamp", "local_time", "localTime", "time", "epoch")
IP_KEYS = ("remote_ip", "client_ip", "remote_addr", "src_ip", "source_ip", "ip")
UNIQUE_KEYS = ("unique_id", "uniqueId", "transaction_id", "transactionId", "id")

class BouncerConfig:
    def __init__(self, raw: configparser.ConfigParser) -> None:
        general = raw["general"] if raw.has_section("general") else {}
        self.log_paths = BouncerConfig._paths(general.get("log_paths", ""))
        self.state_file = general.get("state_file", "/var/lib/modsec-ufw-bouncer/state.json")
        self.poll_interval = max(1, BouncerConfig._int(general.get("poll_interval"), 5))
        self.default_threshold = max(1, BouncerConfig._int(general.get("default_threshold"), 5))
        self.default_window = max(1, BouncerConfig._int(general.get("default_window"), 300))
        self.default_duration = max(0, BouncerConfig._int(general.get("default_block_duration"), 3600))
        self.default_policy = (self.default_threshold, self.default_window, self.default_duration)
        self.whitelist = BouncerConfig._networks(general.get("whitelist", "127.0.0.1 ::1"))
        self.ufw_binary = general.get("ufw_binary", "/usr/sbin/ufw")
        self.ufw_timeout = max(1, BouncerConfig._int(general.get("ufw_timeout"), 10))

        rule_tokens = general.get("enabled_rule_ids", "").strip()
        self.enabled_rule_ids: Optional[Set[str]] = None
        if rule_tokens and rule_tokens.lower() != "all":
            self.enabled_rule_ids = set(BouncerConfig._paths(rule_tokens))

        self.rule_policies: Dict[str, Tuple[int, int, int]] = {}
        for section in raw.sections():
            if not section.startswith("rule:"):
                continue
            rule_id = section[5:].strip()
            if not rule_id:
                raise ValueError("Rule sections must have an ID: [rule:920280]")
            item = raw[section]
            threshold = BouncerConfig._int(item.get("threshold"), 0)
            window = BouncerConfig._int(item.get("window"), 0)
            duration = BouncerConfig._int(item.get("block_duration"), -1)
            if threshold <= 0 or window <= 0 or duration < 0:
                raise ValueError(f"Rule {rule_id} needs threshold > 0, window > 0, and block_duration >= 0")
            self.rule_policies[rule_id] = (threshold, window, duration)

        if self.enabled_rule_ids is not None:
            self.enabled_rule_ids.update(self.rule_policies.keys())

        if not self.log_paths:
            raise ValueError("At least one log path is required in [general] log_paths")
        if not os.path.isfile(self.ufw_binary):
            raise FileNotFoundError(f"ufw binary not found: {self.ufw_binary}")

    @staticmethod
    def _paths(value: str) -> List[str]:
        return [item.strip() for item in re.split(r"[, \t]+", value.strip()) if item.strip()]

    @staticmethod
    def _int(value: Any, default: int) -> int:
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _networks(value: str) -> List[ipaddress._BaseNetwork]:
        return [
            ipaddress.ip_network(token, strict=False)
            for token in re.split(r"[, \t]+", value.strip()) if token
        ]

    def get_rule_policy(self, rule_id: str) -> Tuple[int, int, int]:
        return self.rule_policies.get(rule_id, self.default_policy)

class AuditEvent:
    __slots__ = ("ip", "rule_id", "timestamp", "unique_id")
    def __init__(self, ip: str, rule_id: str, timestamp: float, unique_id: str = "") -> None:
        self.ip = ip
        self.rule_id = rule_id
        self.timestamp = timestamp
        self.unique_id = unique_id
    def __repr__(self) -> str:
        return f"AuditEvent(ip={self.ip!r}, rule_id={self.rule_id!r}, ts={self.timestamp!r}, uid={self.unique_id!r})"

def parse_timestamp(value: str) -> float:
    value = value.strip()
    if not value:
        return time.time()
    patterns = (
        "%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S",
        "%a %b %d %H:%M:%S %Y", "%a %b %d %H:%M:%S %z %Y",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S.%f",
    )
    for pattern in patterns:
        try:
            parsed = dt.datetime.strptime(value, pattern)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.timestamp()
        except ValueError:
            continue
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.timestamp()
    except ValueError:
        pass
    try:
        number = float(value)
        if number > 2147483647000:
            return number / 1000000.0
        if number > 21474836470:
            return number / 1000.0
        return number
    except ValueError:
        return time.time()

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def extract_client(message: str) -> Optional[str]:
    match = CLIENT_RE.search(message)
    if match:
        ip = match.group("ip")
        return ip if is_ip(ip) else None
    for key in ("remote_ip", "client_ip", "remote_addr", "src_ip"):
        match = re.search(rf'"{key}"\s*:\s*"([^"]+)"', message, re.IGNORECASE)
        if match and is_ip(match.group(1)):
            return match.group(1)
    return None

def extract_leading_timestamp(line: str) -> str:
    match = TIMESTAMP_RE.match(line)
    return match.group("ts") if match else ""

def extract_rule_ids(message: str) -> List[str]:
    return [match.group("q1") or match.group("q2") or match.group("bare")
            for match in RULE_ID_RE.finditer(message)
            if match.group("q1") or match.group("q2") or match.group("bare")]

def extract_unique_id(message: str) -> str:
    match = UNIQUE_RE.search(message)
    if match:
        return match.group("q1") or match.group("q2") or match.group("bare") or ""
    match = re.search(r"""(?:unique_id|transaction_id)\s*[:=]\s*["']?([^"'\s,}]+)""", message, re.IGNORECASE)
    return match.group(1) if match else ""

def parse_audit_line(line: str, state: Dict[str, Any]) -> List[AuditEvent]:
    """Parse an Apache/ModSecurity audit or error-log line."""
    match = AUDIT_HEADER.match(line)
    if match:
        section = match.group("section")
        body = match.group("body")
        if section == "A":
            state["section"] = "A"
            state["ip"] = ""
            state["timestamp"] = ""
            state["unique_id"] = ""
            if body:
                parse_audit_body(body, state)
                state["section"] = ""
            return []
        if section == "Z":
            state["section"] = ""
            state["ip"] = ""
            state["timestamp"] = ""
            state["unique_id"] = ""
            return []
        state["section"] = section
        if body:
            return parse_audit_payload(line, state)
        return []
    if state.get("section") == "A":
        parse_audit_body(line, state)
        state["section"] = ""
        return []
    if state.get("section") in ("B", "F", "H"):
        return parse_audit_payload(line, state)
    if "modsecurity" in line.lower() or "mod_security" in line.lower():
        return parse_audit_payload(line, state)
    return []

def parse_audit_body(line: str, state: Dict[str, Any]) -> None:
    match = TIMESTAMP_RE.match(line)
    if match:
        state["timestamp"] = match.group("ts")
        body = match.group("body") or ""
    else:
        timestamp = extract_leading_timestamp(line)
        state["timestamp"] = timestamp or state.get("timestamp", "")
        body = line
    address = extract_client(body)
    if not address:
        address = next((field.strip('"[]') for field in body.split() if is_ip(field.strip('"[]'))), "")
    state["ip"] = address

def parse_audit_payload(line: str, state: Dict[str, Any]) -> List[AuditEvent]:
    timestamp = extract_leading_timestamp(line) or state.get("timestamp", "")
    unique_id = extract_unique_id(line) or state.get("unique_id", "")
    ip = extract_client(line) or state.get("ip", "")
    state["section"] = ""
    return [AuditEvent(ip, rule_id, parse_timestamp(timestamp), unique_id)
            for rule_id in extract_rule_ids(line)]

def event_from_json(value: Any) -> List[AuditEvent]:
    if isinstance(value, list):
        output = []
        for item in value:
            output.extend(event_from_json(item))
        return output
    if not isinstance(value, dict):
        return []
    transaction = value.get("transaction") if isinstance(value.get("transaction"), dict) else value
    ip = ""
    for key in IP_KEYS:
        candidate = transaction.get(key)
        if isinstance(candidate, str) and is_ip(candidate):
            ip = candidate
            break
    timestamp_value = transaction.get("timestamp") or transaction.get("local_time") or transaction.get("time")
    timestamp = parse_timestamp(timestamp_value) if isinstance(timestamp_value, str) and timestamp_value else time.time()
    unique_id = ""
    for key in UNIQUE_KEYS:
        candidate = transaction.get(key)
        if isinstance(candidate, str) and candidate:
            unique_id = candidate
            break
    output: List[AuditEvent] = []
    messages = transaction.get("messages") if isinstance(transaction.get("messages"), list) else []
    for item in messages:
        if not isinstance(item, dict):
            continue
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        rule_id = details.get("ruleId") or item.get("ruleId") or item.get("rule_id") or details.get("id") or item.get("id")
        message = details.get("message") or item.get("message") or ""
        if not rule_id:
            rule_ids = extract_rule_ids(message)
            rule_id = rule_ids[0] if rule_ids else ""
        if not rule_id:
            continue
        item_unique = details.get("unique_id") or details.get("uniqueId") or item.get("unique_id") or unique_id
        item_ip = extract_client(message) or ip
        if not item_ip:
            continue
        output.append(AuditEvent(item_ip, str(rule_id), timestamp, str(item_unique)))
    return output

def process_log(state: Dict[str, Any], path: str) -> List[AuditEvent]:
    try:
        info = os.stat(path)
    except FileNotFoundError:
        LOG.debug("Log path does not exist yet: %s", path)
        return []
    if not stat.S_ISREG(info.st_mode):
        LOG.warning("Ignoring non-regular log path: %s", path)
        return []
    logs = state.setdefault("logs", {})
    entry = logs.get(path)
    offset = 0
    if entry is None:
        offset = info.st_size
    elif entry.get("inode") != info.st_ino:
        LOG.info("Log file rotated; re-reading: %s", path)
        offset = 0
    else:
        offset = min(int(entry.get("offset", 0)), info.st_size)
    parser_state: Dict[str, Any] = {"ip": "", "timestamp": "", "unique_id": "", "section": ""}
    output: List[AuditEvent] = []
    complete_bytes = b""
    try:
        with open(path, "rb") as handle:
            handle.seek(offset)
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                complete_bytes += chunk
                if len(complete_bytes) > LINE_LIMIT:
                    LOG.warning("Log growth for %s exceeded buffer; truncating", path)
                    complete_bytes = complete_bytes[-1024:]
                    break
            last_newline = complete_bytes.rfind(b"\n")
            if last_newline < 0:
                complete_bytes = b""
            else:
                complete_bytes = complete_bytes[: last_newline + 1]
            start = 0
            while start < len(complete_bytes):
                end = complete_bytes.find(b"\n", start)
                if end < 0:
                    break
                raw = complete_bytes[start:end].rstrip(b"\r")
                line = raw.decode("utf-8", errors="replace").strip()
                if len(line) > LINE_LIMIT:
                    LOG.warning("Ignoring oversized log line in %s", path)
                elif line.startswith("{") or line.startswith("["):
                    for event in event_from_json(line):
                        output.append(event)
                else:
                    output.extend(parse_audit_line(line, parser_state))
                start = end + 1
            offset += start
            logs[path] = {"inode": info.st_ino, "offset": offset}
    except (OSError, PermissionError) as exc:
        LOG.error("Unable to read log %s: %s", path, exc)
        return output
    return output

def is_allowed(settings: BouncerConfig, ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in settings.whitelist)

def load_state(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise ValueError("state root is not an object")
    except FileNotFoundError:
        return {"version": 2, "logs": {}, "events": {}, "blocks": {}}
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        LOG.warning("Unable to load state %s (%s); starting empty", path, exc)
        return {"version": 2, "logs": {}, "events": {}, "blocks": {}}
    value.setdefault("version", 2)
    value.setdefault("logs", {})
    value.setdefault("events", {})
    value.setdefault("blocks", {})
    return value

def save_state_atomic(path: str, state: Dict[str, Any]) -> None:
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".modsec-ufw-bouncer-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise

def add_event(state: Dict[str, Any], event: AuditEvent) -> bool:
    if not is_ip(event.ip) or not event.rule_id:
        return False
    per_ip = state.setdefault("events", {}).setdefault(event.ip, {})
    records = per_ip.setdefault(event.rule_id, [])
    if event.unique_id:
        dedup_key = f"{event.rule_id}:{event.unique_id}"
        if any(record.get("uid") == dedup_key for record in records):
            return False
    else:
        dedup_key = ""
    records.append({"t": event.timestamp, "uid": dedup_key})
    if len(records) > 10000:
        del records[:-10000]
    per_ip["_last"] = time.time()
    return True

def prune_events(state: Dict[str, Any]) -> None:
    cutoff = time.time() - 7 * 86400
    events = state.setdefault("events", {})
    for ip in list(events):
        per_ip = events[ip]
        for rule_id in list(per_ip):
            if rule_id == "_last":
                continue
            per_ip[rule_id] = [record for record in per_ip[rule_id] if float(record.get("t", 0)) >= cutoff]
            if not per_ip[rule_id]:
                del per_ip[rule_id]
        if not per_ip:
            del events[ip]

def count_hits(state: Dict[str, Any], ip: str, rule_id: str, window: int) -> int:
    cutoff = time.time() - window
    records = state.get("events", {}).get(ip, {}).get(rule_id, [])
    return sum(1 for record in records if float(record.get("t", 0)) >= cutoff)

def run_ufw(settings: BouncerConfig, args: List[str]) -> Tuple[int, str, str]:
    try:
        completed = subprocess.run(
            [settings.ufw_binary, *args],
            capture_output=True, text=True, timeout=settings.ufw_timeout, check=False,
        )
    except FileNotFoundError:
        return 127, "", "ufw binary not found"
    except subprocess.TimeoutExpired:
        return 124, "", "ufw command timed out"
    except OSError as exc:
        return 126, "", exc.strerror or str(exc)
    if completed.stdout.strip():
        LOG.debug("ufw stdout: %s", completed.stdout.strip())
    if completed.stderr.strip():
        LOG.warning("ufw stderr: %s", completed.stderr.strip())
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()

def ufw_block_exists(settings: BouncerConfig, ip: str) -> bool:
    code, output, _error = run_ufw(settings, ["status"])
    if code != 0:
        return False
    for line in output.splitlines():
        if ip in line and "deny" in line.lower():
            return True
    return False

def add_ufw_block(settings: BouncerConfig, ip: str, rule_id: str) -> Tuple[bool, str, str]:
    if ufw_block_exists(settings, ip):
        return True, "existing-manual-deny", ""
    comment = f"modsec-ufw-bouncer rule={rule_id} epoch={int(time.time())} ip={ip}"[:75]
    code, _, error = run_ufw(
        settings,
        ["insert", "1", "deny", "from", ip, "to", "any", "comment", comment],
    )
    if code != 0:
        return False, "", error or f"ufw exited with status {code}"
    return True, comment, ""

def remove_ufw_block(settings: BouncerConfig, ip: str) -> Tuple[bool, str]:
    code, _, error = run_ufw(settings, ["delete", "deny", "from", ip, "to", "any"])
    if code != 0:
        return False, error or f"ufw exited with status {code}"
    return True, ""

class Bouncer:
    def __init__(self, config_path: str) -> None:
        self.config_path = config_path
        raw = configparser.ConfigParser(interpolation=None)
        if not raw.read(config_path):
            raise FileNotFoundError(f"Unable to read configuration file: {config_path}")
        self.settings = BouncerConfig(raw)
        self.state = load_state(self.settings.state_file)
        self.stop_requested = False

    def stop(self, *_args: Any) -> None:
        self.stop_requested = True

    def parse_logs(self) -> List[AuditEvent]:
        events: List[AuditEvent] = []
        for path in self.settings.log_paths:
            events.extend(process_log(self.state, path))
        if events:
            LOG.info("Parsed %d ModSecurity event(s)", len(events))
        return events

    def should_monitor(self, rule_id: str) -> bool:
        if self.settings.enabled_rule_ids is None:
            return True
        return rule_id in self.settings.enabled_rule_ids

    def store(self, events: List[AuditEvent]) -> List[AuditEvent]:
        stored: List[AuditEvent] = []
        for event in events:
            if not self.should_monitor(event.rule_id) or is_allowed(self.settings, event.ip):
                continue
            if event.ip in self.state.setdefault("blocks", {}):
                continue
            if add_event(self.state, event):
                stored.append(event)
        return stored

    def find_trigger(self) -> Optional[Tuple[str, str, int]]:
        for ip in list(self.state.get("events", {})):
            if ip in self.state.get("blocks", {}) or is_allowed(self.settings, ip):
                continue
            for rule_id in list(self.state["events"][ip]):
                if rule_id == "_last":
                    continue
                threshold, window, _duration = self.settings.get_rule_policy(rule_id)
                hits = count_hits(self.state, ip, rule_id, window)
                if hits >= threshold:
                    return ip, rule_id, hits
        return None

    def block_trigger(self, ip: str, rule_id: str, hits: int) -> bool:
        threshold, _window, duration = self.settings.get_rule_policy(rule_id)
        ok, comment, error = add_ufw_block(self.settings, ip, rule_id)
        if not ok:
            LOG.error("Unable to add UFW deny for ip=%s rule=%s: %s", ip, rule_id, error)
            return False
        expires = 0 if duration == 0 else time.time() + duration
        self.state.setdefault("blocks", {})[ip] = {
            "rule_id": rule_id, "created": time.time(), "expires": expires,
            "comment": comment, "hits": hits, "policy": f"hits>={threshold}",
        }
        expiry_text = "permanent" if expires == 0 else time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expires))
        LOG.warning("Added UFW deny ip=%s rule=%s hits=%d threshold=%d expires=%s", ip, rule_id, hits, threshold, expiry_text)
        self.state.get("events", {}).pop(ip, None)
        return True

    def remove_expired(self) -> None:
        now = time.time()
        blocks = self.state.setdefault("blocks", {})
        for ip in list(blocks):
            expires = float(blocks[ip].get("expires", 0))
            if expires <= 0 or expires > now:
                continue
            ok, error = remove_ufw_block(self.settings, ip)
            if not ok:
                LOG.error("Unable to remove expired UFW deny ip=%s: %s", ip, error)
                continue
            del blocks[ip]
            LOG.info("Removed expired UFW deny ip=%s", ip)

    def cycle(self, dry_run: bool = False) -> None:
        self.store(self.parse_logs())
        prune_events(self.state)
        if not dry_run:
            self.remove_expired()
        while True:
            trigger = self.find_trigger()
            if trigger is None:
                break
            trigger_ip, trigger_rule_id, hits = trigger
            threshold, window, duration = self.settings.get_rule_policy(trigger_rule_id)
            if dry_run:
                LOG.info("DRY RUN would block ip=%s rule=%s hits=%d within=%ds duration=%ds",
                         trigger_ip, trigger_rule_id, hits, window, duration)
                # Clear this rule in the in-memory dry-run state so one pass ends.
                self.state["events"][trigger_ip].pop(trigger_rule_id, None)
                if not self.state["events"][trigger_ip]:
                    self.state["events"].pop(trigger_ip, None)
                continue
            if not self.block_trigger(trigger_ip, trigger_rule_id, hits):
                break

    def run(self, once: bool = False, dry_run: bool = False) -> None:
        try:
            while not self.stop_requested:
                self.cycle(dry_run=dry_run)
                if once:
                    break
                time.sleep(self.settings.poll_interval)
        finally:
            if not dry_run:
                save_state_atomic(self.settings.state_file, self.state)

def setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s", stream=sys.stdout)

def main() -> int:
    parser = argparse.ArgumentParser(description="Manage UFW denies from ModSecurity failures")
    parser.add_argument("-c", "--config", default="/etc/modsec-ufw-bouncer.conf")
    parser.add_argument("--once", action="store_true", help="read logs once, then exit")
    parser.add_argument("--dry-run", action="store_true", help="read logs once and print decisions without changing UFW or state")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase logging")
    args = parser.parse_args()
    setup_logging(args.verbose)
    if args.dry_run:
        args.once = True
    try:
        bouncer = Bouncer(args.config)
        signal.signal(signal.SIGINT, bouncer.stop)
        signal.signal(signal.SIGTERM, bouncer.stop)
        bouncer.run(once=args.once, dry_run=args.dry_run)
    except KeyboardInterrupt:
        pass
    except (FileNotFoundError, ValueError, configparser.Error) as exc:
        LOG.error("Configuration error: %s", exc)
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
