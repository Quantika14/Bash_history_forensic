#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
forensic_bash_syslog_analyzer.py

Herramienta defensiva para adquisición y análisis de .bash_history y logs tipo syslog/auth.log.
Genera un informe HTML con estadísticas y línea temporal cruzada.

Autor: Jorge Coronado 
Company: QuantiKa14
LinkedIn: https://www.linkedin.com/in/jorge-coronado-quantika14/
Requisitos: Python 3.9+
Uso recomendado: ejecutar como root solo si necesita acceder a /root o historiales de otros usuarios.

Notas forenses importantes:
- Bash solo guarda horas exactas si HISTTIMEFORMAT estaba activado. En ese caso, .bash_history contiene
  líneas tipo #1715342400 antes de cada comando.
- Syslog/auth.log registra algunos comandos, especialmente sudo/cron, pero NO todos los comandos de shell.
- Si no hay timestamps en bash_history, el informe lo declara expresamente y evita atribuir horas exactas.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import getpass
import gzip
import hashlib
import html
import json
import os
import platform
import re
import shutil
import socket
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

VERSION = "1.0.0"

DEFAULT_BASH_PATHS = ["/root/.bash_history", "/home/*/.bash_history"]
DEFAULT_SYSLOG_PATHS = [
    "/var/log/syslog*",
    "/var/log/auth.log*",
    "/var/log/messages*",
    "/var/log/secure*",
    "/var/log/kern.log*",
    "/var/log/daemon.log*",
]

TRADITIONAL_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
ISO_SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

RISK_PATTERNS = [
    ("descarga/remoto", re.compile(r"\b(curl|wget|fetch)\b.*\b(http|https|ftp)://", re.I)),
    ("pipe a shell", re.compile(r"\b(curl|wget)\b.*\|\s*(sh|bash|python|perl)", re.I)),
    ("reverse shell", re.compile(r"(/dev/tcp/|bash\s+-i|nc\s+.*(-e|/bin/sh|/bin/bash)|ncat\s+.*(-e|--sh-exec)|socat\s+.*exec)", re.I)),
    ("borrado/destrucción", re.compile(r"\b(rm\s+-[a-zA-Z]*r[f]?|shred|wipe|srm|dd\s+if=)", re.I)),
    ("limpieza de huellas", re.compile(r"(history\s+-c|unset\s+HISTFILE|>\s*~?/\.bash_history|truncate\s+-s\s*0|journalctl\s+--vacuum|logrotate)", re.I)),
    ("permisos peligrosos", re.compile(r"\bchmod\s+(-R\s+)?(777|666|a\+w)\b", re.I)),
    ("persistencia", re.compile(r"\b(crontab|systemctl\s+enable|update-rc\.d|rc\.local|/etc/systemd|/etc/cron|authorized_keys)\b", re.I)),
    ("usuario/credenciales", re.compile(r"\b(useradd|adduser|usermod|passwd|chpasswd|visudo|sudoers)\b", re.I)),
    ("red/firewall", re.compile(r"\b(iptables|nft|ufw|firewall-cmd|ssh|scp|rsync|sshpass|netcat|nc|nmap|masscan)\b", re.I)),
    ("base de datos", re.compile(r"\b(pg_dump|psql|mysqldump|mysql|mongoexport|mongodump|sqlite3)\b", re.I)),
    ("contenedores/cloud", re.compile(r"\b(docker|kubectl|aws|gcloud|az)\b", re.I)),
    ("compresión/exfiltración", re.compile(r"\b(tar|zip|gzip|7z|rar)\b.*\b(/home|/var|/etc|/root|\.ssh|postgres|mysql|www|html)\b", re.I)),
]

COMMAND_FROM_SYSLOG_PATTERNS = [
    re.compile(r"sudo:.*?\b(?P<user>[A-Za-z0-9_.-]+)\s*:\s*.*?COMMAND=(?P<cmd>.+)$", re.I),
    re.compile(r"CRON\[\d+\]: \((?P<user>[^)]+)\) CMD \((?P<cmd>.*)\)$", re.I),
]

LOGIN_PATTERNS = [
    ("ssh accepted", re.compile(r"sshd\[\d+\]: Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)", re.I)),
    ("ssh failed", re.compile(r"sshd\[\d+\]: Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)", re.I)),
    ("session opened", re.compile(r"pam_unix\((?P<service>[^:]+):session\): session opened for user (?P<user>\S+)", re.I)),
    ("session closed", re.compile(r"pam_unix\((?P<service>[^:]+):session\): session closed for user (?P<user>\S+)", re.I)),
    ("su", re.compile(r"\bsu\[\d+\]:.*session opened for user (?P<user>\S+)", re.I)),
]


def now_local() -> dt.datetime:
    return dt.datetime.now().astimezone()


def iso_now() -> str:
    return now_local().isoformat(timespec="seconds")


def safe_name(path: str | Path) -> str:
    p = str(path)
    return p.strip("/").replace("/", "__").replace("\\", "__") or "root"


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def expand_paths(patterns: Iterable[str]) -> List[Path]:
    found: List[Path] = []
    for pattern in patterns:
        matches = sorted(Path("/").glob(pattern.strip("/"))) if pattern.startswith("/") else sorted(Path().glob(pattern))
        for m in matches:
            if m.is_file() and m not in found:
                found.append(m)
    return found


def ensure_case_dir(case_dir: Optional[str] = None) -> Path:
    if case_dir:
        base = Path(case_dir).expanduser().resolve()
    else:
        base = Path.cwd() / f"case_bash_syslog_{now_local().strftime('%Y%m%d_%H%M%S')}"
    base.mkdir(parents=True, exist_ok=True)
    (base / "acquisition" / "bash_history").mkdir(parents=True, exist_ok=True)
    (base / "acquisition" / "syslog").mkdir(parents=True, exist_ok=True)
    (base / "analysis").mkdir(parents=True, exist_ok=True)
    (base / "reports").mkdir(parents=True, exist_ok=True)
    return base


def load_manifest(case_dir: Path) -> List[dict]:
    manifest_path = case_dir / "manifest.json"
    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def save_manifest(case_dir: Path, manifest: List[dict]) -> None:
    (case_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    with (case_dir / "manifest.csv").open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "type", "source_path", "acquired_path", "sha256", "size_bytes", "source_mtime",
            "source_ctime", "acquired_at", "error"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in manifest:
            writer.writerow(row)


def write_case_metadata(case_dir: Path) -> None:
    metadata = {
        "tool": "forensic_bash_syslog_analyzer.py",
        "version": VERSION,
        "created_at": iso_now(),
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "platform": platform.platform(),
        "python": sys.version,
        "username_running_script": getpass.getuser(),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "gid": os.getgid() if hasattr(os, "getgid") else None,
        "timezone": str(now_local().tzinfo),
        "argv": sys.argv,
    }
    (case_dir / "case_metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")


def acquire_files(case_dir: Path, evidence_type: str, source_patterns: List[str]) -> List[dict]:
    manifest = load_manifest(case_dir)
    target_subdir = "bash_history" if evidence_type == "bash_history" else "syslog"
    target_dir = case_dir / "acquisition" / target_subdir
    target_dir.mkdir(parents=True, exist_ok=True)

    found = expand_paths(source_patterns)
    print(f"[+] {evidence_type}: localizados {len(found)} fichero(s).")

    for src in found:
        row = {
            "type": evidence_type,
            "source_path": str(src),
            "acquired_path": "",
            "sha256": "",
            "size_bytes": None,
            "source_mtime": None,
            "source_ctime": None,
            "acquired_at": iso_now(),
            "error": "",
        }
        try:
            st = src.stat()
            row["size_bytes"] = st.st_size
            row["source_mtime"] = dt.datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(timespec="seconds")
            row["source_ctime"] = dt.datetime.fromtimestamp(st.st_ctime).astimezone().isoformat(timespec="seconds")
            dest = target_dir / safe_name(src)
            if dest.exists():
                stamp = now_local().strftime("%Y%m%d_%H%M%S")
                dest = target_dir / f"{safe_name(src)}__{stamp}"
            shutil.copy2(src, dest)
            row["acquired_path"] = str(dest)
            row["sha256"] = sha256_file(dest)
            print(f"    OK {src} -> {dest.name} sha256={row['sha256'][:16]}...")
        except Exception as e:
            row["error"] = repr(e)
            print(f"    ERROR {src}: {e}")
        manifest.append(row)

    save_manifest(case_dir, manifest)
    write_case_metadata(case_dir)
    return manifest


@dataclass
class BashCommand:
    source_file: str
    user: str
    command: str
    timestamp: Optional[str]
    epoch: Optional[int]
    order: int
    file_mtime: Optional[str]
    risk_tags: List[str]


@dataclass
class SyslogEvent:
    source_file: str
    timestamp: Optional[str]
    raw_timestamp: str
    host: str
    process: str
    pid: Optional[str]
    message: str
    category: str
    user: Optional[str]
    src_ip: Optional[str]
    command: Optional[str]
    risk_tags: List[str]


def user_from_bash_path(path: Path) -> str:
    name = path.name
    # El nombre adquirido conserva la ruta con __. Ej: home__jorge__.bash_history
    if "root__.bash_history" in name or name == "root__.bash_history" or name.endswith("root__.bash_history"):
        return "root"
    m = re.search(r"(?:^|__)home__(?P<user>[^_][^_]*?)__\.bash_history", name)
    if m:
        return m.group("user")
    # Fallback para rutas originales o nombres raros
    parts = str(path).split(os.sep)
    if ".bash_history" in parts and "home" in parts:
        try:
            return parts[parts.index("home") + 1]
        except Exception:
            pass
    return "unknown"


def risk_tags_for_command(command: str) -> List[str]:
    tags = []
    for tag, pattern in RISK_PATTERNS:
        if pattern.search(command):
            tags.append(tag)
    return tags


def read_text_lines(path: Path) -> Iterable[str]:
    opener = gzip.open if path.name.endswith(".gz") else open
    mode = "rt"
    try:
        with opener(path, mode, encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line.rstrip("\n")
    except OSError:
        # Algunos ficheros .gz rotados corruptos o incompletos: intentar lectura binaria simple.
        with path.open("rb") as f:
            for raw in f:
                yield raw.decode("utf-8", errors="replace").rstrip("\n")


def parse_bash_history_file(path: Path) -> List[BashCommand]:
    out: List[BashCommand] = []
    user = user_from_bash_path(path)
    file_mtime = None
    try:
        file_mtime = dt.datetime.fromtimestamp(path.stat().st_mtime).astimezone().isoformat(timespec="seconds")
    except Exception:
        pass

    pending_epoch: Optional[int] = None
    order = 0
    multiline_buffer: List[str] = []

    def flush_command(cmd: str, epoch: Optional[int], idx: int) -> None:
        if not cmd.strip():
            return
        ts = None
        if epoch is not None:
            try:
                ts = dt.datetime.fromtimestamp(epoch).astimezone().isoformat(timespec="seconds")
            except Exception:
                ts = None
        out.append(BashCommand(
            source_file=str(path),
            user=user,
            command=cmd,
            timestamp=ts,
            epoch=epoch,
            order=idx,
            file_mtime=file_mtime,
            risk_tags=risk_tags_for_command(cmd),
        ))

    for line in read_text_lines(path):
        # Bash con HISTTIMEFORMAT guarda una línea #epoch justo antes del comando.
        if re.fullmatch(r"#\d{9,11}", line.strip()):
            if multiline_buffer:
                order += 1
                flush_command("\n".join(multiline_buffer), pending_epoch, order)
                multiline_buffer = []
            try:
                pending_epoch = int(line.strip()[1:])
            except Exception:
                pending_epoch = None
            continue

        # Bash puede guardar comandos multilínea con barras invertidas. Conservamos el bloque.
        if line.endswith("\\"):
            multiline_buffer.append(line)
            continue
        if multiline_buffer:
            multiline_buffer.append(line)
            order += 1
            flush_command("\n".join(multiline_buffer), pending_epoch, order)
            multiline_buffer = []
            pending_epoch = None
            continue

        order += 1
        flush_command(line, pending_epoch, order)
        pending_epoch = None

    if multiline_buffer:
        order += 1
        flush_command("\n".join(multiline_buffer), pending_epoch, order)

    return out


def parse_iso_ts(s: str) -> Optional[dt.datetime]:
    try:
        clean = s.replace("Z", "+00:00")
        # Soporte para +0100 sin dos puntos
        if re.search(r"[+-]\d{4}$", clean):
            clean = clean[:-5] + clean[-5:-2] + ":" + clean[-2:]
        obj = dt.datetime.fromisoformat(clean)
        if obj.tzinfo is None:
            obj = obj.astimezone()
        return obj.astimezone()
    except Exception:
        return None


def infer_year_for_traditional_log(path: Path) -> int:
    try:
        return dt.datetime.fromtimestamp(path.stat().st_mtime).astimezone().year
    except Exception:
        return now_local().year


def parse_syslog_timestamp_traditional(mon: str, day: str, t: str, year: int) -> Optional[dt.datetime]:
    try:
        month = MONTHS[mon]
        hour, minute, second = map(int, t.split(":"))
        return dt.datetime(year, month, int(day), hour, minute, second).astimezone()
    except Exception:
        return None


def classify_syslog_event(proc: str, msg: str) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    text = f"{proc}: {msg}"
    for category, pat in LOGIN_PATTERNS:
        m = pat.search(text)
        if m:
            return category, m.groupdict().get("user"), m.groupdict().get("src_ip"), None

    for pat in COMMAND_FROM_SYSLOG_PATTERNS:
        m = pat.search(text)
        if m:
            user = m.groupdict().get("user")
            cmd = m.groupdict().get("cmd")
            category = "sudo command" if "sudo" in text.lower() else "cron command"
            return category, user, None, cmd

    if "authentication failure" in text.lower():
        user_match = re.search(r"user=(\S+)", text)
        return "auth failure", user_match.group(1) if user_match else None, None, None
    if "session opened" in text.lower():
        user_match = re.search(r"user\s+(\S+)", text)
        return "session opened", user_match.group(1) if user_match else None, None, None
    if "session closed" in text.lower():
        user_match = re.search(r"user\s+(\S+)", text)
        return "session closed", user_match.group(1) if user_match else None, None, None
    if "COMMAND=" in text:
        cmd = text.split("COMMAND=", 1)[1].strip()
        return "command", None, None, cmd
    return "system", None, None, None


def parse_syslog_file(path: Path) -> List[SyslogEvent]:
    out: List[SyslogEvent] = []
    fallback_year = infer_year_for_traditional_log(path)

    for line in read_text_lines(path):
        raw_ts = ""
        timestamp = None
        host = ""
        proc = ""
        pid = None
        msg = line

        mi = ISO_SYSLOG_RE.match(line)
        mt = None if mi else TRADITIONAL_SYSLOG_RE.match(line)

        if mi:
            gd = mi.groupdict()
            raw_ts = gd["ts"]
            obj = parse_iso_ts(gd["ts"])
            timestamp = obj.isoformat(timespec="seconds") if obj else None
            host = gd.get("host") or ""
            proc = gd.get("proc") or ""
            pid = gd.get("pid")
            msg = gd.get("msg") or ""
        elif mt:
            gd = mt.groupdict()
            raw_ts = f"{gd['mon']} {gd['day']} {gd['time']}"
            obj = parse_syslog_timestamp_traditional(gd["mon"], gd["day"], gd["time"], fallback_year)
            timestamp = obj.isoformat(timespec="seconds") if obj else None
            host = gd.get("host") or ""
            proc = gd.get("proc") or ""
            pid = gd.get("pid")
            msg = gd.get("msg") or ""
        else:
            # Línea no estándar: se conserva sin descartar.
            raw_ts = ""

        category, user, src_ip, cmd = classify_syslog_event(proc, msg)
        out.append(SyslogEvent(
            source_file=str(path),
            timestamp=timestamp,
            raw_timestamp=raw_ts,
            host=host,
            process=proc,
            pid=pid,
            message=msg,
            category=category,
            user=user,
            src_ip=src_ip,
            command=cmd,
            risk_tags=risk_tags_for_command(cmd or msg),
        ))
    return out


def parse_all(case_dir: Path) -> Tuple[List[BashCommand], List[SyslogEvent]]:
    bash_dir = case_dir / "acquisition" / "bash_history"
    syslog_dir = case_dir / "acquisition" / "syslog"

    bash_commands: List[BashCommand] = []
    for f in sorted(bash_dir.glob("*")):
        if f.is_file():
            bash_commands.extend(parse_bash_history_file(f))

    syslog_events: List[SyslogEvent] = []
    for f in sorted(syslog_dir.glob("*")):
        if f.is_file():
            syslog_events.extend(parse_syslog_file(f))

    analysis_dir = case_dir / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    (analysis_dir / "bash_commands.json").write_text(
        json.dumps([asdict(x) for x in bash_commands], indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (analysis_dir / "syslog_events.json").write_text(
        json.dumps([asdict(x) for x in syslog_events], indent=2, ensure_ascii=False), encoding="utf-8"
    )

    with (analysis_dir / "bash_commands.csv").open("w", newline="", encoding="utf-8") as f:
        fieldnames = list(asdict(bash_commands[0]).keys()) if bash_commands else list(BashCommand("", "", "", None, None, 0, None, []).__dict__.keys())
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for x in bash_commands:
            row = asdict(x)
            row["risk_tags"] = ";".join(row["risk_tags"])
            writer.writerow(row)

    with (analysis_dir / "syslog_events.csv").open("w", newline="", encoding="utf-8") as f:
        fieldnames = list(asdict(syslog_events[0]).keys()) if syslog_events else list(SyslogEvent("", None, "", "", "", None, "", "", None, None, None, []).__dict__.keys())
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for x in syslog_events:
            row = asdict(x)
            row["risk_tags"] = ";".join(row["risk_tags"])
            writer.writerow(row)

    print(f"[+] Parseados {len(bash_commands)} comandos de bash_history y {len(syslog_events)} eventos syslog/auth.")
    return bash_commands, syslog_events


def dt_from_iso(s: Optional[str]) -> Optional[dt.datetime]:
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s)
    except Exception:
        try:
            return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None


def first_token(command: str) -> str:
    command = command.strip()
    if not command:
        return ""
    # Elimina prefijos habituales: sudo, env VAR=, nohup, time
    parts = command.split()
    while parts and parts[0] in {"sudo", "nohup", "time", "command"}:
        parts = parts[1:]
    if parts and "=" in parts[0] and not parts[0].startswith("/"):
        # Variables de entorno antes del comando
        while parts and "=" in parts[0] and not parts[0].startswith("/"):
            parts = parts[1:]
    if not parts:
        return ""
    return Path(parts[0]).name


def build_correlations(
    bash_commands: List[BashCommand],
    syslog_events: List[SyslogEvent],
    window_seconds: int = 300,
) -> Dict[int, List[SyslogEvent]]:
    """Correlaciona comandos bash con eventos syslog cercanos por tiempo y/o comandos sudo/cron similares."""
    events_with_dt = [(e, dt_from_iso(e.timestamp)) for e in syslog_events if e.timestamp]
    correlated: Dict[int, List[SyslogEvent]] = defaultdict(list)

    for idx, cmd in enumerate(bash_commands):
        cmd_dt = dt_from_iso(cmd.timestamp)
        if cmd_dt:
            low = cmd_dt - dt.timedelta(seconds=window_seconds)
            high = cmd_dt + dt.timedelta(seconds=window_seconds)
            for ev, ev_dt in events_with_dt:
                if not ev_dt or ev_dt < low or ev_dt > high:
                    continue
                # Relación fuerte si usuario coincide, si hay comando en syslog, o si son eventos de sesión/ssh.
                same_user = bool(ev.user and cmd.user and ev.user == cmd.user)
                command_overlap = bool(ev.command and (ev.command in cmd.command or cmd.command in ev.command))
                session_related = ev.category in {"ssh accepted", "session opened", "session closed", "su", "sudo command", "cron command"}
                if same_user or command_overlap or session_related:
                    correlated[idx].append(ev)
        else:
            # Sin hora en bash_history: solo match textual con sudo/cron si existe.
            compact_cmd = re.sub(r"\s+", " ", cmd.command.strip())
            if not compact_cmd:
                continue
            for ev in syslog_events:
                if ev.command:
                    ev_cmd = re.sub(r"\s+", " ", ev.command.strip())
                    if ev_cmd and (ev_cmd == compact_cmd or ev_cmd in compact_cmd or compact_cmd in ev_cmd):
                        correlated[idx].append(ev)
    return correlated


def counter_by_hour(items: Iterable[str]) -> Counter:
    c = Counter()
    for ts in items:
        d = dt_from_iso(ts)
        if d:
            c[f"{d.hour:02d}:00"] += 1
    return c


def counter_by_day(items: Iterable[str]) -> Counter:
    c = Counter()
    for ts in items:
        d = dt_from_iso(ts)
        if d:
            c[d.date().isoformat()] += 1
    return c


def html_table(headers: List[str], rows: Iterable[Iterable[object]], max_rows: Optional[int] = None) -> str:
    out = ["<table>", "<thead><tr>" + "".join(f"<th>{html.escape(str(h))}</th>" for h in headers) + "</tr></thead>", "<tbody>"]
    count = 0
    for row in rows:
        if max_rows is not None and count >= max_rows:
            break
        out.append("<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>")
        count += 1
    out.append("</tbody></table>")
    return "\n".join(out)


def mini_bar_chart(counter: Counter, title: str, limit: int = 20) -> str:
    if not counter:
        return f"<h3>{html.escape(title)}</h3><p class='muted'>Sin datos.</p>"
    maxv = max(counter.values()) or 1
    rows = []
    for key, val in counter.most_common(limit):
        pct = int((val / maxv) * 100)
        rows.append(f"<div class='barrow'><span class='barlabel'>{html.escape(str(key))}</span><div class='bar'><div style='width:{pct}%'></div></div><span class='barval'>{val}</span></div>")
    return f"<h3>{html.escape(title)}</h3><div class='bars'>{''.join(rows)}</div>"


def command_sort_key(cmd: BashCommand) -> Tuple[int, str, int]:
    if cmd.timestamp:
        return (0, cmd.timestamp, cmd.order)
    return (1, cmd.source_file, cmd.order)


def generate_html_report(
    case_dir: Path,
    bash_commands: List[BashCommand],
    syslog_events: List[SyslogEvent],
    window_seconds: int = 300,
) -> Path:
    report_path = case_dir / "reports" / "bash_syslog_report.html"
    manifest = load_manifest(case_dir)
    correlations = build_correlations(bash_commands, syslog_events, window_seconds=window_seconds)

    total_cmds = len(bash_commands)
    timestamped = sum(1 for c in bash_commands if c.timestamp)
    untimed = total_cmds - timestamped
    unique_cmds = len(set(c.command for c in bash_commands))
    users = Counter(c.user for c in bash_commands)
    top_bins = Counter(first_token(c.command) for c in bash_commands if first_token(c.command))
    risky_commands = [c for c in bash_commands if c.risk_tags]
    risky_syslog = [e for e in syslog_events if e.risk_tags]
    syslog_categories = Counter(e.category for e in syslog_events)
    syslog_users = Counter(e.user for e in syslog_events if e.user)
    ips = Counter(e.src_ip for e in syslog_events if e.src_ip)

    bash_by_hour = counter_by_hour(c.timestamp for c in bash_commands if c.timestamp)
    syslog_by_hour = counter_by_hour(e.timestamp for e in syslog_events if e.timestamp)
    bash_by_day = counter_by_day(c.timestamp for c in bash_commands if c.timestamp)
    syslog_by_day = counter_by_day(e.timestamp for e in syslog_events if e.timestamp)

    command_timeline_rows = []
    for idx, c in sorted(enumerate(bash_commands), key=lambda t: command_sort_key(t[1])):
        corr = correlations.get(idx, [])[:5]
        corr_txt = " | ".join(
            f"{e.timestamp or e.raw_timestamp} {e.category} {e.user or ''} {e.command or e.message[:120]}" for e in corr
        )
        command_timeline_rows.append([
            c.timestamp or "SIN HORA EN BASH_HISTORY",
            c.user,
            c.command,
            ", ".join(c.risk_tags),
            corr_txt,
            Path(c.source_file).name,
        ])

    # Timeline cruzada: mezcla eventos con hora de bash y syslog command/login events.
    mixed = []
    for c in bash_commands:
        if c.timestamp:
            mixed.append((c.timestamp, "bash_history", c.user, "command", c.command, ", ".join(c.risk_tags), Path(c.source_file).name))
    for e in syslog_events:
        if e.timestamp and (e.category != "system" or e.command or e.risk_tags):
            mixed.append((e.timestamp, "syslog", e.user or "", e.category, e.command or e.message, ", ".join(e.risk_tags), Path(e.source_file).name))
    mixed.sort(key=lambda x: x[0])

    caveat = ""
    if untimed:
        caveat = f"""
        <div class='warning'>
          <strong>Limitación temporal:</strong> {untimed} de {total_cmds} comandos no tienen timestamp en bash_history.
          En Bash, la hora exacta solo aparece si estaba activado <code>HISTTIMEFORMAT</code>. Para esos comandos, el informe no atribuye una hora exacta salvo coincidencia textual con sudo/cron en syslog.
        </div>
        """

    manifest_rows = []
    for row in manifest:
        manifest_rows.append([
            row.get("type", ""), row.get("source_path", ""), row.get("acquired_path", ""),
            row.get("sha256", ""), row.get("size_bytes", ""), row.get("source_mtime", ""), row.get("error", "")
        ])

    risky_rows = []
    for c in sorted(risky_commands, key=command_sort_key):
        risky_rows.append([c.timestamp or "SIN HORA", c.user, c.command, ", ".join(c.risk_tags), Path(c.source_file).name])
    for e in risky_syslog:
        risky_rows.append([e.timestamp or e.raw_timestamp or "SIN HORA", e.user or "", e.command or e.message, ", ".join(e.risk_tags), Path(e.source_file).name])

    report_html = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Informe forense bash_history + syslog</title>
<style>
:root {{ --bg:#0f172a; --card:#111827; --ink:#e5e7eb; --muted:#9ca3af; --line:#334155; --accent:#38bdf8; --warn:#f59e0b; --bad:#ef4444; --ok:#22c55e; }}
body {{ margin:0; font-family: Arial, Helvetica, sans-serif; background:#f3f4f6; color:#111827; }}
header {{ background:linear-gradient(135deg,#0f172a,#1e293b); color:white; padding:28px 36px; }}
header h1 {{ margin:0 0 8px; font-size:28px; }}
header p {{ margin:4px 0; color:#cbd5e1; }}
main {{ padding:24px 36px 60px; }}
.card {{ background:white; border:1px solid #e5e7eb; border-radius:14px; padding:18px; margin:0 0 18px; box-shadow:0 1px 2px rgba(0,0,0,.04); }}
.grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:12px; }}
.metric {{ background:#f8fafc; border:1px solid #e5e7eb; border-radius:12px; padding:14px; }}
.metric .n {{ font-size:28px; font-weight:700; color:#0f172a; }}
.metric .l {{ color:#64748b; font-size:13px; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th, td {{ border-bottom:1px solid #e5e7eb; padding:8px; vertical-align:top; text-align:left; }}
th {{ background:#f8fafc; position:sticky; top:0; z-index:1; }}
code {{ background:#f1f5f9; padding:1px 4px; border-radius:5px; }}
.warning {{ background:#fffbeb; border:1px solid #fcd34d; border-left:5px solid var(--warn); padding:12px; border-radius:10px; margin:12px 0; }}
.muted {{ color:#64748b; }}
.badge {{ display:inline-block; background:#e0f2fe; color:#0369a1; padding:2px 8px; border-radius:999px; font-size:12px; }}
.scroll {{ max-height:680px; overflow:auto; border:1px solid #e5e7eb; border-radius:10px; }}
.bars {{ display:flex; flex-direction:column; gap:7px; }}
.barrow {{ display:grid; grid-template-columns:130px 1fr 50px; gap:10px; align-items:center; font-size:13px; }}
.bar {{ background:#e5e7eb; height:12px; border-radius:999px; overflow:hidden; }}
.bar div {{ background:#38bdf8; height:100%; }}
.barlabel {{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.barval {{ text-align:right; color:#475569; }}
.footer {{ color:#64748b; font-size:12px; margin-top:20px; }}
</style>
</head>
<body>
<header>
  <h1>Informe forense de Bash History + Syslog</h1>
  <p>Generado: {html.escape(iso_now())}</p>
  <p>Caso: <code>{html.escape(str(case_dir))}</code> · Ventana de correlación: ±{window_seconds} segundos</p>
</header>
<main>
  <section class="card">
    <h2>Resumen ejecutivo</h2>
    <div class="grid">
      <div class="metric"><div class="n">{total_cmds}</div><div class="l">Comandos bash_history</div></div>
      <div class="metric"><div class="n">{timestamped}</div><div class="l">Comandos con hora exacta</div></div>
      <div class="metric"><div class="n">{untimed}</div><div class="l">Comandos sin hora</div></div>
      <div class="metric"><div class="n">{unique_cmds}</div><div class="l">Comandos únicos</div></div>
      <div class="metric"><div class="n">{len(syslog_events)}</div><div class="l">Eventos syslog/auth</div></div>
      <div class="metric"><div class="n">{len(risky_commands) + len(risky_syslog)}</div><div class="l">Eventos/comandos con indicadores de riesgo</div></div>
    </div>
    {caveat}
    <p class="muted">Este informe no sustituye una valoración pericial completa: la correlación temporal depende de que bash_history contenga timestamps, de la conservación de syslog/auth.log y de que el sistema auditara los comandos relevantes.</p>
  </section>

  <section class="card">
    <h2>Estadísticas</h2>
    <div class="grid">
      <div>{mini_bar_chart(top_bins, "Binarios/comandos más usados", 15)}</div>
      <div>{mini_bar_chart(users, "Usuarios en bash_history", 15)}</div>
      <div>{mini_bar_chart(syslog_categories, "Categorías syslog", 15)}</div>
      <div>{mini_bar_chart(ips, "IPs en accesos SSH", 15)}</div>
    </div>
  </section>

  <section class="card">
    <h2>Actividad por hora y día</h2>
    <div class="grid">
      <div>{mini_bar_chart(bash_by_hour, "Comandos bash por hora", 24)}</div>
      <div>{mini_bar_chart(syslog_by_hour, "Eventos syslog por hora", 24)}</div>
      <div>{mini_bar_chart(bash_by_day, "Comandos bash por día", 30)}</div>
      <div>{mini_bar_chart(syslog_by_day, "Eventos syslog por día", 30)}</div>
    </div>
  </section>

  <section class="card">
    <h2>Indicadores de riesgo detectados</h2>
    <div class="scroll">
      {html_table(["Fecha/hora", "Usuario", "Comando o evento", "Indicadores", "Fuente"], risky_rows, max_rows=500)}
    </div>
  </section>

  <section class="card">
    <h2>Línea temporal cruzada bash_history + syslog</h2>
    <p class="muted">Incluye comandos de bash con timestamp y eventos syslog relevantes: sudo, cron, SSH, sesiones, fallos de autenticación e indicadores de riesgo.</p>
    <div class="scroll">
      {html_table(["Fecha/hora", "Origen", "Usuario", "Tipo", "Detalle", "Indicadores", "Fuente"], mixed, max_rows=3000)}
    </div>
  </section>

  <section class="card">
    <h2>Comandos bash_history y correlación cercana en syslog</h2>
    <p class="muted">La correlación busca eventos de syslog/auth dentro de la ventana indicada, coincidencia de usuario, eventos de sesión/SSH/sudo/cron y coincidencias textuales de comando.</p>
    <div class="scroll">
      {html_table(["Fecha/hora bash", "Usuario", "Comando", "Indicadores", "Eventos syslog correlacionados", "Fuente"], command_timeline_rows, max_rows=5000)}
    </div>
  </section>

  <section class="card">
    <h2>Cadena de custodia técnica / manifiesto de adquisición</h2>
    <p class="muted">Listado de evidencias copiadas y hash SHA-256 calculado sobre la copia adquirida.</p>
    <div class="scroll">
      {html_table(["Tipo", "Ruta original", "Ruta adquirida", "SHA-256", "Tamaño", "mtime original", "Error"], manifest_rows, max_rows=1000)}
    </div>
  </section>

  <section class="card">
    <h2>Interpretación pericial recomendada</h2>
    <ul>
      <li>Los comandos con hora exacta proceden de bash_history con líneas <code>#epoch</code>; son los más útiles para reconstrucción temporal.</li>
      <li>Los comandos sin timestamp solo permiten conocer existencia y orden relativo dentro del fichero, no fecha/hora exacta.</li>
      <li>Los eventos de <code>sudo</code>, <code>CRON</code>, <code>sshd</code>, <code>su</code> y sesiones PAM ayudan a contextualizar quién pudo estar conectado y qué comandos privilegiados se ejecutaron.</li>
      <li>La ausencia de un comando en syslog no implica que no se ejecutara: muchos comandos de usuario no se registran en syslog.</li>
      <li>Si existe <code>auditd</code>, <code>journalctl</code>, <code>wtmp/btmp/lastlog</code> o EDR, conviene cruzarlos también para reforzar atribución y cronología.</li>
    </ul>
  </section>

  <div class="footer">Generado por forensic_bash_syslog_analyzer.py v{VERSION}</div>
</main>
</body>
</html>"""
    report_path.write_text(report_html, encoding="utf-8")
    print(f"[+] Informe HTML generado: {report_path}")
    return report_path


def ask_paths(defaults: List[str], label: str) -> List[str]:
    print(f"\nRutas por defecto para {label}:")
    for d in defaults:
        print(f"  - {d}")
    raw = input("Introduce rutas/globs separados por coma o pulsa Enter para usar las rutas por defecto: ").strip()
    if not raw:
        return defaults
    return [x.strip() for x in raw.split(",") if x.strip()]


def menu(case_dir: Path) -> None:
    bash_patterns = DEFAULT_BASH_PATHS[:]
    syslog_patterns = DEFAULT_SYSLOG_PATHS[:]
    window_seconds = 300

    while True:
        print("\n" + "=" * 76)
        print("Herramienta forense bash_history + syslog")
        print(f"Caso actual: {case_dir}")
        print("=" * 76)
        print("1) Configurar rutas de bash_history")
        print("2) Configurar rutas de syslog/auth/messages")
        print("3) Adquirir bash_history")
        print("4) Adquirir syslog/auth/messages")
        print("5) Analizar evidencias adquiridas")
        print("6) Generar informe HTML")
        print("7) Ejecutar todo: adquirir + analizar + informe")
        print("8) Cambiar ventana de correlación")
        print("9) Salir")
        choice = input("Selecciona una opción: ").strip()

        if choice == "1":
            bash_patterns = ask_paths(DEFAULT_BASH_PATHS, "bash_history")
        elif choice == "2":
            syslog_patterns = ask_paths(DEFAULT_SYSLOG_PATHS, "syslog/auth/messages")
        elif choice == "3":
            acquire_files(case_dir, "bash_history", bash_patterns)
        elif choice == "4":
            acquire_files(case_dir, "syslog", syslog_patterns)
        elif choice == "5":
            parse_all(case_dir)
        elif choice == "6":
            bash_commands, syslog_events = parse_all(case_dir)
            generate_html_report(case_dir, bash_commands, syslog_events, window_seconds=window_seconds)
        elif choice == "7":
            acquire_files(case_dir, "bash_history", bash_patterns)
            acquire_files(case_dir, "syslog", syslog_patterns)
            bash_commands, syslog_events = parse_all(case_dir)
            generate_html_report(case_dir, bash_commands, syslog_events, window_seconds=window_seconds)
        elif choice == "8":
            raw = input(f"Ventana actual ±{window_seconds}s. Nueva ventana en segundos: ").strip()
            try:
                window_seconds = max(0, int(raw))
            except Exception:
                print("[!] Valor no válido.")
        elif choice == "9":
            print("Saliendo.")
            return
        else:
            print("[!] Opción no válida.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Adquisición y análisis forense de bash_history y syslog/auth.log con informe HTML.")
    parser.add_argument("--case-dir", help="Directorio de caso. Si no existe, se crea.")
    parser.add_argument("--all", action="store_true", help="Adquirir bash_history + syslog, analizar y generar informe sin menú.")
    parser.add_argument("--acquire-bash", action="store_true", help="Solo adquirir bash_history.")
    parser.add_argument("--acquire-syslog", action="store_true", help="Solo adquirir syslog/auth/messages.")
    parser.add_argument("--analyze", action="store_true", help="Parsear evidencias adquiridas.")
    parser.add_argument("--report", action="store_true", help="Generar informe HTML desde evidencias adquiridas.")
    parser.add_argument("--bash-path", action="append", default=[], help="Ruta/glob de bash_history. Puede repetirse.")
    parser.add_argument("--syslog-path", action="append", default=[], help="Ruta/glob de syslog/auth/messages. Puede repetirse.")
    parser.add_argument("--window", type=int, default=300, help="Ventana de correlación en segundos. Por defecto: 300.")
    args = parser.parse_args()

    case_dir = ensure_case_dir(args.case_dir)
    write_case_metadata(case_dir)

    bash_patterns = args.bash_path or DEFAULT_BASH_PATHS
    syslog_patterns = args.syslog_path or DEFAULT_SYSLOG_PATHS

    if args.all:
        acquire_files(case_dir, "bash_history", bash_patterns)
        acquire_files(case_dir, "syslog", syslog_patterns)
        bash_commands, syslog_events = parse_all(case_dir)
        generate_html_report(case_dir, bash_commands, syslog_events, window_seconds=args.window)
        return 0

    did_something = False
    if args.acquire_bash:
        did_something = True
        acquire_files(case_dir, "bash_history", bash_patterns)
    if args.acquire_syslog:
        did_something = True
        acquire_files(case_dir, "syslog", syslog_patterns)
    if args.analyze:
        did_something = True
        parse_all(case_dir)
    if args.report:
        did_something = True
        bash_commands, syslog_events = parse_all(case_dir)
        generate_html_report(case_dir, bash_commands, syslog_events, window_seconds=args.window)

    if not did_something:
        menu(case_dir)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
