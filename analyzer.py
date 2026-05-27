#!/usr/bin/env python3
"""
analyzer.py – Real-time Nginx/Apache log analyzer with email alerting.
Self-contained single file. Only dependency: pyyaml

Install:  pip install pyyaml
Usage:
    python analyzer.py                          # uses config.yaml in same folder
    python analyzer.py --config path/to.yaml
    python analyzer.py --log /var/log/nginx/access.log
    python analyzer.py --log test_access.log --replay   # process from start
    python analyzer.py --dry-run               # detect only, no emails sent
    python analyzer.py --verbose               # print every parsed line

config.yaml example (create this in the same folder):
─────────────────────────────────────────────────────
log:
  path: "test_access.log"

thresholds:
  http_errors:
    window_seconds: 60
    min_count: 10
  brute_force:
    window_seconds: 60
    min_requests: 100
  slow_response:
    threshold_ms: 2000
  keywords:
    enabled: true
    terms:
      - "sql injection"
      - "../"
      - "<script"
      - "eval("
      - "/etc/passwd"
      - "union select"

alerting:
  cooldown_seconds: 300

email:
  enabled: true
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  use_tls: true
  username: "you@gmail.com"
  password: "your-app-password"
  from_addr: "you@gmail.com"
  to_addrs:
    - "alerts@yourcompany.com"
  subject_prefix: "[LogAlert]"
─────────────────────────────────────────────────────
"""

# ══════════════════════════════════════════════════════════════════════════════
#  PARSER
# ══════════════════════════════════════════════════════════════════════════════

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

_COMBINED_RE = re.compile(
    r'(?P<ip>\S+)\s+'
    r'\S+\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    r'(?:\s+(?P<rt>[\d.]+))?'
)
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass
class LogEntry:
    raw: str
    ip: str
    user: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    size: int
    referer: str = ""
    user_agent: str = ""
    response_time_ms: Optional[float] = None

    @property
    def is_error(self) -> bool:
        return self.status >= 400


def _parse_request(raw: str) -> tuple:
    parts = raw.split(" ", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return "UNKNOWN", raw, ""


def parse_line(line: str) -> Optional[LogEntry]:
    line = line.rstrip("\n")
    m = _COMBINED_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("time"), _TIME_FMT)
    except ValueError:
        return None

    method, path, protocol = _parse_request(m.group("request"))
    size_raw = m.group("size")
    size = int(size_raw) if size_raw.isdigit() else 0
    rt_raw = m.group("rt")
    rt_ms = float(rt_raw) * 1000 if rt_raw else None

    return LogEntry(
        raw=line, ip=m.group("ip"), user=m.group("user"),
        timestamp=ts, method=method, path=path, protocol=protocol,
        status=int(m.group("status")), size=size,
        referer=m.group("referer") or "",
        user_agent=m.group("ua") or "",
        response_time_ms=rt_ms,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

import time
from collections import defaultdict, deque
from enum import Enum, auto


class AlertType(Enum):
    HTTP_ERROR_SPIKE = auto()
    BRUTE_FORCE      = auto()
    SLOW_RESPONSE    = auto()
    KEYWORD_MATCH    = auto()


@dataclass
class Alert:
    alert_type: AlertType
    message: str
    entry: LogEntry
    extra: dict = field(default_factory=dict)

    def subject(self) -> str:
        return {
            AlertType.HTTP_ERROR_SPIKE: "HTTP Error Spike",
            AlertType.BRUTE_FORCE:      "Brute Force / Rate Abuse",
            AlertType.SLOW_RESPONSE:    "Slow Response Detected",
            AlertType.KEYWORD_MATCH:    "Suspicious Keyword",
        }[self.alert_type]

    def body(self) -> str:
        lines = [
            f"Alert Type : {self.subject()}",
            f"Message    : {self.message}",
            f"IP         : {self.entry.ip}",
            f"Time       : {self.entry.timestamp}",
            f"Request    : {self.entry.method} {self.entry.path}",
            f"Status     : {self.entry.status}",
        ]
        if self.entry.response_time_ms is not None:
            lines.append(f"Resp Time  : {self.entry.response_time_ms:.0f} ms")
        for k, v in self.extra.items():
            lines.append(f"{k:<11}: {v}")
        lines += ["", f"Raw line: {self.entry.raw}"]
        return "\n".join(lines)


class _SlidingWindow:
    def __init__(self, window_seconds: int):
        self._window = window_seconds
        self._events: deque = deque()

    def add(self) -> int:
        now = time.monotonic()
        self._events.append(now)
        cutoff = now - self._window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()
        return len(self._events)


class Detector:
    def __init__(self, config: dict):
        t  = config.get("thresholds", {})
        a  = config.get("alerting", {})
        ec = t.get("http_errors", {})
        bf = t.get("brute_force", {})
        sr = t.get("slow_response", {})
        kw = t.get("keywords", {})

        self._err_window_sec   = ec.get("window_seconds", 60)
        self._err_min_count    = ec.get("min_count", 10)
        self._err_codes        = set(ec.get("status_codes", range(400, 600)))
        self._bf_window_sec    = bf.get("window_seconds", 60)
        self._bf_min_requests  = bf.get("min_requests", 100)
        self._slow_ms          = sr.get("threshold_ms", 2000)
        self._kw_enabled       = kw.get("enabled", True)
        self._kw_terms         = [t.lower() for t in kw.get("terms", [])]
        self._cooldown_sec     = a.get("cooldown_seconds", 300)
        self._last_alert: dict = {}
        self._error_window     = _SlidingWindow(self._err_window_sec)
        self._ip_windows       = defaultdict(lambda: _SlidingWindow(self._bf_window_sec))

    def process(self, entry: LogEntry) -> list:
        alerts = []
        alerts.extend(self._check_http_errors(entry))
        alerts.extend(self._check_brute_force(entry))
        alerts.extend(self._check_slow_response(entry))
        alerts.extend(self._check_keywords(entry))
        return alerts

    def _cooled(self, key) -> bool:
        last = self._last_alert.get(key)
        return last is None or (time.monotonic() - last) >= self._cooldown_sec

    def _mark(self, key) -> None:
        self._last_alert[key] = time.monotonic()

    def _check_http_errors(self, entry: LogEntry) -> list:
        if entry.status not in self._err_codes:
            return []
        count = self._error_window.add()
        if count >= self._err_min_count:
            key = (AlertType.HTTP_ERROR_SPIKE, "global")
            if not self._cooled(key):
                return []
            self._mark(key)
            return [Alert(AlertType.HTTP_ERROR_SPIKE,
                f"{count} HTTP errors in last {self._err_window_sec}s "
                f"(threshold: {self._err_min_count})",
                entry, {"Error count": count, "Window": f"{self._err_window_sec}s"})]
        return []

    def _check_brute_force(self, entry: LogEntry) -> list:
        count = self._ip_windows[entry.ip].add()
        if count >= self._bf_min_requests:
            key = (AlertType.BRUTE_FORCE, entry.ip)
            if not self._cooled(key):
                return []
            self._mark(key)
            return [Alert(AlertType.BRUTE_FORCE,
                f"IP {entry.ip} sent {count} requests in {self._bf_window_sec}s "
                f"(threshold: {self._bf_min_requests})",
                entry, {"Req count": count, "Window": f"{self._bf_window_sec}s"})]
        return []

    def _check_slow_response(self, entry: LogEntry) -> list:
        if entry.response_time_ms is None or entry.response_time_ms < self._slow_ms:
            return []
        key = (AlertType.SLOW_RESPONSE, entry.path)
        if not self._cooled(key):
            return []
        self._mark(key)
        return [Alert(AlertType.SLOW_RESPONSE,
            f"Slow response: {entry.response_time_ms:.0f} ms for "
            f"{entry.method} {entry.path} (threshold: {self._slow_ms:.0f} ms)",
            entry, {"Response time": f"{entry.response_time_ms:.0f} ms"})]

    def _check_keywords(self, entry: LogEntry) -> list:
        if not self._kw_enabled:
            return []
        haystack = (entry.path + " " + entry.user_agent).lower()
        for term in self._kw_terms:
            if term in haystack:
                key = (AlertType.KEYWORD_MATCH, term, entry.ip)
                if not self._cooled(key):
                    continue
                self._mark(key)
                return [Alert(AlertType.KEYWORD_MATCH,
                    f"Suspicious keyword '{term}' in request from {entry.ip}: "
                    f"{entry.method} {entry.path}",
                    entry, {"Keyword": term})]
        return []


# ══════════════════════════════════════════════════════════════════════════════
#  TAILER
# ══════════════════════════════════════════════════════════════════════════════

import os
import threading
import logging

logger = logging.getLogger(__name__)


class LogTailer:
    def __init__(self, path: str, callback, poll_interval: float = 0.1, seek_end: bool = True):
        self.path          = path
        self.callback      = callback
        self.poll_interval = poll_interval
        self.seek_end      = seek_end
        self._stop         = threading.Event()
        self._thread       = threading.Thread(target=self._run, daemon=True, name="log-tailer")

    def start(self):
        logger.info("Watching: %s", self.path)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _run(self):
        fh, inode = None, None
        while not self._stop.is_set():
            try:
                cur_inode = os.stat(self.path).st_ino
            except FileNotFoundError:
                time.sleep(2)
                continue
            if fh is None or cur_inode != inode:
                if fh:
                    fh.close()
                fh = open(self.path, "r", encoding="utf-8", errors="replace")
                if self.seek_end:
                    fh.seek(0, os.SEEK_END)
                inode = cur_inode
            for line in fh:
                try:
                    self.callback(line)
                except Exception as exc:
                    logger.error("Callback error: %s", exc)
            time.sleep(self.poll_interval)
        if fh:
            fh.close()


# ══════════════════════════════════════════════════════════════════════════════
#  EMAIL ALERTER
# ══════════════════════════════════════════════════════════════════════════════

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

_ALERT_COLORS = {
    "HTTP_ERROR_SPIKE": "#e74c3c",
    "BRUTE_FORCE":      "#e67e22",
    "SLOW_RESPONSE":    "#f1c40f",
    "KEYWORD_MATCH":    "#8e44ad",
}


def _render_html(alert: Alert) -> str:
    color  = _ALERT_COLORS.get(alert.alert_type.name, "#3498db")
    entry  = alert.entry
    extras = "".join(
        f"<tr><td style='padding:4px 12px;color:#666'>{k}</td>"
        f"<td style='padding:4px 12px'>{v}</td></tr>"
        for k, v in alert.extra.items()
    )
    rt_row = (
        f"<tr><td style='padding:4px 12px;color:#666'>Response Time</td>"
        f"<td style='padding:4px 12px'>{entry.response_time_ms:.0f} ms</td></tr>"
        if entry.response_time_ms is not None else ""
    )
    return f"""<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:20px">
  <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1);overflow:hidden">
    <div style="background:{color};padding:16px 20px"><h2 style="margin:0;color:#fff">⚠ {alert.subject()}</h2></div>
    <div style="padding:20px">
      <p style="font-size:15px;margin-top:0">{alert.message}</p>
      <table style="width:100%;border-collapse:collapse;font-size:14px">
        <tr style="background:#f9f9f9"><td style="padding:4px 12px;color:#666">IP</td><td style="padding:4px 12px">{entry.ip}</td></tr>
        <tr><td style="padding:4px 12px;color:#666">Time</td><td style="padding:4px 12px">{entry.timestamp}</td></tr>
        <tr style="background:#f9f9f9"><td style="padding:4px 12px;color:#666">Request</td><td style="padding:4px 12px"><code>{entry.method} {entry.path}</code></td></tr>
        <tr><td style="padding:4px 12px;color:#666">Status</td><td style="padding:4px 12px">{entry.status}</td></tr>
        {rt_row}{extras}
      </table>
      <details style="margin-top:16px"><summary style="cursor:pointer;color:#666;font-size:13px">Raw log line</summary>
        <pre style="background:#f5f5f5;padding:10px;border-radius:4px;font-size:12px;overflow-x:auto;white-space:pre-wrap">{entry.raw}</pre>
      </details>
    </div>
    <div style="background:#f9f9f9;padding:10px 20px;font-size:12px;color:#999">Generated by Log Analyzer</div>
  </div></body></html>"""


class EmailAlerter:
    def __init__(self, config: dict):
        ec = config.get("email", {})
        self.enabled       = ec.get("enabled", False)
        self.smtp_host     = ec.get("smtp_host", "localhost")
        self.smtp_port     = ec.get("smtp_port", 587)
        self.use_tls       = ec.get("use_tls", True)
        self.username      = ec.get("username", "")
        self.password      = ec.get("password", "")
        self.from_addr     = ec.get("from_addr", self.username)
        self.to_addrs      = ec.get("to_addrs", [])
        self.subject_prefix = ec.get("subject_prefix", "[LogAlert]")

    def send(self, alert: Alert) -> None:
        if not self.enabled or not self.to_addrs:
            return
        threading.Thread(target=self._send, args=(alert,), daemon=True).start()

    def _send(self, alert: Alert) -> None:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"{self.subject_prefix} {alert.subject()}"
        msg["From"]    = self.from_addr
        msg["To"]      = ", ".join(self.to_addrs)
        msg.attach(MIMEText(alert.body(), "plain"))
        msg.attach(MIMEText(_render_html(alert), "html"))
        try:
            if self.use_tls:
                s = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10)
                s.ehlo(); s.starttls(); s.ehlo()
            else:
                s = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=10)
            if self.username:
                s.login(self.username, self.password)
            s.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            s.quit()
            logger.info("Alert email sent: %s → %s", alert.subject(), self.to_addrs)
        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP auth failed – check username/password in config.yaml")
        except (smtplib.SMTPException, OSError) as exc:
            logger.error("Email send failed: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

import argparse
import signal
import sys
from pathlib import Path

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class Stats:
    def __init__(self):
        self.lines_read = self.lines_parsed = self.lines_skipped = self.alerts_fired = 0
        self.start_time = time.monotonic()

    def summary(self):
        elapsed = time.monotonic() - self.start_time
        print(f"\n── Session Summary {'─'*25}")
        print(f"  Runtime      : {elapsed:.1f}s")
        print(f"  Lines read   : {self.lines_read}")
        print(f"  Lines parsed : {self.lines_parsed}")
        print(f"  Skipped      : {self.lines_skipped}")
        print(f"  Alerts fired : {self.alerts_fired}")
        print(f"{'─'*44}")


def main():
    ap = argparse.ArgumentParser(description="Real-time Nginx/Apache log analyzer.")
    ap.add_argument("--config",   default="config.yaml")
    ap.add_argument("--log",      help="Override log path from config")
    ap.add_argument("--replay",   action="store_true", help="Read from start of file")
    ap.add_argument("--dry-run",  action="store_true", help="Detect but don't email")
    ap.add_argument("--verbose",  action="store_true", help="Print every parsed line")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"Error: config file not found: {args.config}")
        print("Create a config.yaml in this folder. See the header of this file for an example.")
        sys.exit(1)

    with cfg_path.open() as f:
        config = yaml.safe_load(f)

    log_path = args.log or config.get("log", {}).get("path", "")
    if not log_path or not Path(log_path).exists():
        print(f"Error: log file not found: {log_path!r}")
        print("Set log.path in config.yaml or pass --log <path>")
        sys.exit(1)

    detector = Detector(config)
    alerter  = EmailAlerter(config)
    stats    = Stats()

    if args.dry_run:
        logger.info("DRY-RUN mode – alerts will NOT be emailed.")

    def handle_line(line: str):
        stats.lines_read += 1
        entry = parse_line(line)
        if entry is None:
            stats.lines_skipped += 1
            return
        stats.lines_parsed += 1
        if args.verbose:
            logger.info("%s %s %s %s", entry.ip, entry.method, entry.path, entry.status)
        for alert in detector.process(entry):
            stats.alerts_fired += 1
            logger.warning("ALERT [%s] %s", alert.alert_type.name, alert.message)
            if not args.dry_run:
                alerter.send(alert)

    tailer = LogTailer(log_path, handle_line, seek_end=not args.replay)

    def shutdown(sig, frame):
        print()
        logger.info("Shutting down…")
        tailer.stop()
        stats.summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("Log Analyzer started. Press Ctrl+C to stop.")
    tailer.start()
    while tailer.is_alive():
        time.sleep(1)
    stats.summary()


if __name__ == "__main__":
    main()
