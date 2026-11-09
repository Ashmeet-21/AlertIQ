"""
Sends a realistic mix of security events to a running AlertIQ backend.
Every run uses fresh IPs, so the dedup window doesn't hide repeat runs.

    .\\venv\\Scripts\\python scripts\\send_sample_alerts.py
    .\\venv\\Scripts\\python scripts\\send_sample_alerts.py --url http://localhost:8000 --key <INGEST_API_KEY>
"""
import argparse
import os
import random
import httpx


def rnd_public():
    # TEST-NET and well-known scanner ranges, never real customer IPs
    return random.choice(["45.33.32.", "185.220.101.", "198.51.100.", "203.0.113."]) + str(random.randint(2, 250))


def rnd_internal():
    return f"192.168.{random.randint(2, 250)}.{random.randint(2, 250)}"


def events():
    return [
        # external brute force against the domain controller -> AI/rules should call it real
        ("login_failure", "identity_system",
         {"src_ip": rnd_public(), "host": "dc01", "user": "administrator", "attempts": 34, "timespan_sec": 60,
          "message": "34 failed logons for administrator in 60s"}),
        # internal user mistyping a password -> likely benign
        ("login_failure", "identity_system",
         {"src_ip": rnd_internal(), "host": "laptop-114", "user": "priya.k", "attempts": 2,
          "message": "2 failed logons, then success"}),
        # PII in the message: should show up redacted on the dashboard
        ("suspicious_email", "email_gateway",
         {"src_ip": rnd_public(), "user": "finance.team", "message":
          "Invoice request from ceo.urgent@freemail.example asking to call +1 604-555-0199, password=Winter2026"}),
        # explicit CRITICAL -> escalated straight to P1, skips AI
        ("malware_detected", "edr",
         {"src_ip": rnd_internal(), "host": "fileserver01", "severity": "CRITICAL",
          "message": "Ransomware behaviour: mass file renames to *.locked"}),
        # very high count -> escalated
        ("port_scan", "firewall",
         {"src_ip": rnd_public(), "dest_ip": "10.0.0.2", "count": 1200, "message": "SYN scan on 1200 ports"}),
        # routine noise -> suppressed
        ("heartbeat", "agent", {"src_ip": rnd_internal(), "host": "web-03"}),
        # outbound beacon to a hosting provider
        ("c2_beacon", "network_ids",
         {"src_ip": rnd_public(), "dest_ip": rnd_internal(), "host": "laptop-207",
          "message": "Periodic 60s HTTPS beacon with fixed JA3 fingerprint"}),
        # privilege change at night
        ("privilege_escalation", "identity_system",
         {"src_ip": rnd_internal(), "host": "dc01.corp.local", "user": "svc_backup",
          "message": "svc_backup added to Domain Admins at 03:12"}),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--key", default=os.environ.get("INGEST_API_KEY", ""))
    args = ap.parse_args()
    headers = {"X-API-Key": args.key} if args.key else {}

    for event_type, source_type, payload in events():
        r = httpx.post(f"{args.url}/alerts/ingest", headers=headers, timeout=10,
                       json={"event_type": event_type, "source_type": source_type, "payload": payload})
        body = r.json()
        print(f"{r.status_code}  {event_type:<22} {body.get('status', body.get('detail'))}")
    print("\nOpen the dashboard: alerts update live as the pipeline finishes each one.")


if __name__ == "__main__":
    main()
