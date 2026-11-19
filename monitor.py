"""Read one packet metadata record per CSV row and report suspicious traffic."""

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import urllib.request

from integrations import normalize, threat_index


def audit(path, audit_action, outcome="success", **details):
    entry = {"time": datetime.now(timezone.utc).isoformat(), "action": audit_action,
             "outcome": outcome, "details": details}
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def notify(message, audit_path, send):
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat = os.getenv("TELEGRAM_CHAT_ID")
    slack = os.getenv("SLACK_WEBHOOK_URL", "")
    channels = {
        "telegram": (f"https://api.telegram.org/bot{token}/sendMessage",
                     {"chat_id": chat, "text": message}, bool(token and chat)),
        "slack": (slack, {"text": message},
                  slack.startswith("https://hooks.slack.com/services/")),
    }
    opener = urllib.request.build_opener(NoRedirect())
    for channel, (url, payload, configured) in channels.items():
        outcome = "preview"
        if send:
            outcome = "unconfigured"
            if configured:
                request = urllib.request.Request(
                    url, json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"}, method="POST")
                try:
                    with opener.open(request, timeout=5) as response:
                        body = response.read(65536)
                    accepted = (json.loads(body).get("ok") is True if channel == "telegram"
                                else body.strip() == b"ok")
                    outcome = "sent" if accepted else "failed"
                except (OSError, ValueError, AttributeError):
                    outcome = "failed"
        print(f"{channel}: {outcome}")
        audit(audit_path, "notification", outcome, channel=channel)


def analyze(path, threshold, min_sources, threats):
    windows = defaultdict(Counter)
    by_protocol = Counter()
    ioc_matches = Counter()
    with path.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            stamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                raise ValueError("Packet timestamp must include a time zone")
            second = stamp.astimezone(timezone.utc).replace(microsecond=0).isoformat()
            src = str(ipaddress.ip_address(row["source_ip"]))
            dst = str(ipaddress.ip_address(row["destination_ip"]))
            windows[second, dst][src] += 1
            by_protocol[row["protocol"].upper()] += 1
            for address in {src, dst}.intersection(threats):
                ioc_matches[address] += 1
    alerts = []
    for (second, dst), sources in sorted(windows.items()):
        pps = sum(sources.values())
        if pps >= threshold and len(sources) >= min_sources:
            alerts.append({"time": second, "destination": dst, "pps": pps,
                           "unique_sources": len(sources)})
    matches = [{"ip": ip, "packets": count, "feeds": sorted(threats[ip])}
               for ip, count in sorted(ioc_matches.items())]
    return {"packets": sum(by_protocol.values()), "by_protocol": dict(by_protocol),
            "threshold_pps": threshold, "min_sources": min_sources,
            "ddos_suspicions": alerts, "ioc_matches": matches}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packets", type=Path, default=Path("examples/packets.csv"))
    parser.add_argument("--pps", type=int, default=100)
    parser.add_argument("--min-sources", type=int, default=3)
    parser.add_argument("--audit", type=Path, default=Path("audit.jsonl"))
    parser.add_argument("--report", type=Path, default=Path("report.json"))
    parser.add_argument("--send", action="store_true")
    for provider in ("aws", "azure", "biometric", "misp", "otx"):
        parser.add_argument(f"--{provider}", type=Path,
                            default=Path(f"examples/{provider}.json"))
    args = parser.parse_args()
    if args.pps < 1 or args.min_sources < 1:
        parser.error("Thresholds must be positive")
    if args.audit.resolve() == args.report.resolve():
        parser.error("Use separate paths for audit and report")
    audit(args.audit, "monitor_start", pps=args.pps, min_sources=args.min_sources)
    try:
        threats = threat_index(read_json(args.misp), read_json(args.otx))
        report = analyze(args.packets, args.pps, args.min_sources, threats)
        for provider in ("aws", "azure", "biometric"):
            events = list(normalize(provider, read_json(getattr(args, provider))))
            for event in events:
                audit(args.audit, "imported_event", event.pop("outcome"), **event)
        for alert in report["ddos_suspicions"]:
            audit(args.audit, "possible_ddos", **alert)
        for match in report["ioc_matches"]:
            audit(args.audit, "threat_indicator_match", **match)
        alerts = report["ddos_suspicions"]
        matches = report["ioc_matches"]
        if alerts or matches:
            notify(f"Network monitor: suspicious DDoS windows: {len(alerts)}. "
                   f"Threat indicator matches: {len(matches)}. See local audit.",
                   args.audit, args.send)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError) as error:
        audit(args.audit, "monitor_finish", "failed", error_type=type(error).__name__)
        parser.exit(1, f"Input or output error: {error}\n")
    audit(args.audit, "monitor_finish", packets=report["packets"])
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
