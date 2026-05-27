#!/usr/bin/env python3
"""
generate_logs.py – Fake Nginx access log generator for testing.

Writes realistic log lines to a file in real-time.
Run this in one terminal, run the analyzer in another.

Usage:
    python generate_logs.py                      # writes to test_access.log
    python generate_logs.py --out /tmp/test.log
    python generate_logs.py --scenario brute     # trigger brute-force alert
    python generate_logs.py --scenario errors    # trigger error spike alert
    python generate_logs.py --scenario slow      # trigger slow response alert
    python generate_logs.py --scenario keyword   # trigger keyword alert
    python generate_logs.py --scenario all       # cycle through all scenarios
    python generate_logs.py --rate 5             # lines per second (default: 2)
"""

import argparse
import random
import time
from datetime import datetime, timezone

# ── Sample data pools ─────────────────────────────────────────────────────────

NORMAL_IPS = [f"192.168.1.{i}" for i in range(1, 20)] + \
             ["10.0.0.5", "10.0.0.8", "172.16.0.3", "203.0.113.42"]

ATTACKER_IP = "45.33.32.156"       # used for brute-force scenario
BOT_IP      = "198.51.100.23"      # used for keyword scenario

USERS  = ["-", "alice", "bob", "-", "-", "-"]

PATHS_OK = [
    "/", "/index.html", "/about", "/contact", "/products",
    "/api/v1/users", "/api/v1/orders", "/static/main.css",
    "/static/app.js", "/images/logo.png", "/favicon.ico",
    "/blog/post-1", "/blog/post-2", "/search?q=shoes",
    "/api/v1/health", "/dashboard", "/login",
]

PATHS_4XX = [
    "/admin",           # 403
    "/wp-login.php",    # 404
    "/.env",            # 404
    "/nonexistent",     # 404
    "/api/v1/secret",   # 401
    "/rate-limited",    # 429
]

PATHS_5XX = [
    "/api/v1/crash",
    "/api/v1/timeout",
    "/broken-endpoint",
]

MALICIOUS_PATHS = [
    "/search?q=<script>alert(1)</script>",
    "/page?id=1+union+select+*+from+users",
    "/../../../../etc/passwd",
    "/api?cmd=eval(base64_decode(xxx))",
    "/login?user=admin%27+OR+%271%27%3D%271",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]

METHODS = ["GET"] * 8 + ["POST"] * 2


# ── Log line builder ──────────────────────────────────────────────────────────

def make_line(ip: str, path: str, status: int, response_time_s: float) -> str:
    now = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S %z")
    method = random.choice(METHODS)
    user   = random.choice(USERS)
    size   = random.randint(200, 8000)
    ua     = random.choice(USER_AGENTS)
    return (
        f'{ip} - {user} [{now}] "{method} {path} HTTP/1.1" '
        f'{status} {size} "-" "{ua}" {response_time_s:.3f}'
    )


def normal_line() -> str:
    ip   = random.choice(NORMAL_IPS)
    path = random.choice(PATHS_OK)
    rt   = round(random.uniform(0.05, 0.4), 3)
    return make_line(ip, path, 200, rt)


# ── Scenarios ─────────────────────────────────────────────────────────────────

def run_normal(f, rate: float) -> None:
    print("  → Normal traffic…")
    for _ in range(int(rate * 10)):
        f.write(normal_line() + "\n")
        f.flush()
        time.sleep(1 / rate)


def run_error_spike(f, rate: float) -> None:
    print("  ⚡ Injecting HTTP error spike (15 × 500 errors)…")
    for _ in range(15):
        ip   = random.choice(NORMAL_IPS)
        path = random.choice(PATHS_5XX)
        rt   = round(random.uniform(0.5, 2.0), 3)
        f.write(make_line(ip, path, 500, rt) + "\n")
        f.flush()
        time.sleep(0.2)


def run_brute_force(f, rate: float) -> None:
    print("  ⚡ Injecting brute-force attack (120 rapid requests from one IP)…")
    for _ in range(120):
        path = random.choice(["/login", "/admin", "/wp-login.php"])
        rt   = round(random.uniform(0.01, 0.1), 3)
        status = random.choice([200, 401, 403])
        f.write(make_line(ATTACKER_IP, path, status, rt) + "\n")
        f.flush()
        time.sleep(0.05)   # 20 req/s → 120 in 6 s


def run_slow_response(f, rate: float) -> None:
    print("  ⚡ Injecting slow response (8 000 ms)…")
    ip = random.choice(NORMAL_IPS)
    f.write(make_line(ip, "/api/v1/heavy-query", 200, 8.0) + "\n")
    f.flush()


def run_keyword(f, rate: float) -> None:
    print("  ⚡ Injecting suspicious keyword request…")
    path = random.choice(MALICIOUS_PATHS)
    f.write(make_line(BOT_IP, path, 400, 0.05) + "\n")
    f.flush()


# ── Main ──────────────────────────────────────────────────────────────────────

SCENARIO_MAP = {
    "errors":  run_error_spike,
    "brute":   run_brute_force,
    "slow":    run_slow_response,
    "keyword": run_keyword,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Fake Nginx log generator.")
    parser.add_argument("--out",      default="test_access.log", help="Output log file")
    parser.add_argument("--rate",     type=float, default=2.0,   help="Lines/sec during normal traffic")
    parser.add_argument("--scenario", default="all",
                        choices=["all", "normal", "errors", "brute", "slow", "keyword"],
                        help="Which scenario to run")
    args = parser.parse_args()

    print(f"\n📝 Writing fake logs → {args.out}")
    print("   Open another terminal and run:")
    print(f"   python analyzer.py --log {args.out} --replay\n")
    print("Press Ctrl+C to stop.\n")

    with open(args.out, "a", buffering=1) as f:

        if args.scenario == "normal":
            while True:
                f.write(normal_line() + "\n")
                f.flush()
                time.sleep(1 / args.rate)

        elif args.scenario in SCENARIO_MAP:
            SCENARIO_MAP[args.scenario](f, args.rate)
            print("Done. Check the analyzer output.")

        else:  # "all" – cycle: normal → spike → normal → brute → normal → slow → keyword
            cycle = 0
            while True:
                cycle += 1
                print(f"\n── Cycle {cycle} ──────────────────────────")

                print("  Normal traffic (10 s)…")
                run_normal(f, args.rate)

                run_error_spike(f, args.rate)
                run_normal(f, args.rate)

                run_brute_force(f, args.rate)
                run_normal(f, args.rate)

                run_slow_response(f, args.rate)
                run_normal(f, args.rate)

                run_keyword(f, args.rate)

                print(f"\n  Cycle {cycle} complete. Sleeping 30 s before next cycle…")
                time.sleep(30)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGenerator stopped.")
