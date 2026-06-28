import re
from datetime import datetime, timedelta
from collections import defaultdict

# ============================================================
# detector.py — brute-force detection from a syslog-style auth log
#
# Strategy:
#   1. Parse every line for failed/accepted SSH login events.
#   2. Group failed attempts by source IP with timestamps.
#   3. Use a sliding time window: for each failure, count how
#      many other failures from the same IP fall within
#      WINDOW_MINUTES minutes of it. If the count crosses
#      THRESHOLD, flag the IP as a brute-force source.
#   4. Check whether the flagged IP ever achieved a successful
#      login — that tells us if the attack worked.
# ============================================================

LOG_FILE      = "auth.log"
THRESHOLD     = 5    # failed attempts within the window to trigger alert
WINDOW_MINUTES = 5   # sliding window size in minutes

# Regex patterns for the two event types we care about.
# Matches lines like:
#   Jun 27 09:15:03 webserver sshd[1005]: Failed password for root from 1.2.3.4 port 43212 ssh2
#   Jun 27 09:15:14 webserver sshd[1014]: Accepted password for ubuntu from 1.2.3.4 port 43221 ssh2
FAILED_RE   = re.compile(
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+).*Failed password for \S+ from (\S+)"
)
ACCEPTED_RE = re.compile(
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+).*Accepted password for \S+ from (\S+)"
)

# syslog timestamps omit the year; assume current year for parsing
CURRENT_YEAR = datetime.now().year


def parse_timestamp(raw: str) -> datetime:
    """Convert 'Jun 27 09:15:03' to a datetime object."""
    return datetime.strptime(f"{CURRENT_YEAR} {raw.strip()}", "%Y %b %d %H:%M:%S")


def load_events(path: str):
    """Read the log file and return two structures:
    - failures: dict mapping IP -> list of failure timestamps (sorted)
    - successes: set of IPs that had at least one successful login
    """
    failures  = defaultdict(list)   # ip -> [datetime, ...]
    successes = set()               # ips with a successful login

    with open(path) as f:
        for line in f:
            m = FAILED_RE.search(line)
            if m:
                ts, ip = parse_timestamp(m.group(1)), m.group(2)
                failures[ip].append(ts)
                continue

            m = ACCEPTED_RE.search(line)
            if m:
                successes.add(m.group(2))

    # Sort each IP's failure list chronologically
    for ip in failures:
        failures[ip].sort()

    return failures, successes


def detect_brute_force(failures: dict, successes: set):
    """Sliding-window scan over each IP's failure timestamps.

    For each failure event at time T, count how many failures
    from the same IP fall in [T, T + WINDOW_MINUTES). If that
    count >= THRESHOLD, the IP is flagged.
    """
    window = timedelta(minutes=WINDOW_MINUTES)
    flagged = {}   # ip -> max failures seen in any window

    for ip, timestamps in failures.items():
        n = len(timestamps)
        max_in_window = 0

        # Two-pointer: left marks the start of the current window
        left = 0
        for right in range(n):
            # Advance left until the window fits within WINDOW_MINUTES
            while timestamps[right] - timestamps[left] >= window:
                left += 1
            count = right - left + 1
            if count > max_in_window:
                max_in_window = count

        if max_in_window >= THRESHOLD:
            flagged[ip] = max_in_window

    return flagged


def report(flagged: dict, failures: dict, successes: set):
    if not flagged:
        print("[OK] No brute-force activity detected.")
        return

    print(f"[!] Brute-force detection results (threshold: {THRESHOLD} failures "
          f"within {WINDOW_MINUTES} min)\n")

    for ip, peak in sorted(flagged.items(), key=lambda x: -x[1]):
        total   = len(failures[ip])
        success = ip in successes
        status  = "SUCCEEDED — attacker gained access!" if success else "blocked (no successful login)"

        print(f"  ALERT: {ip}")
        print(f"    Failed attempts : {total} total, {peak} within {WINDOW_MINUTES}-minute window")
        print(f"    Attack outcome  : {status}")
        first, last = failures[ip][0], failures[ip][-1]
        print(f"    Time range      : {first.strftime('%H:%M:%S')} – {last.strftime('%H:%M:%S')}")
        print()


def main():
    print("=== bruteforcelab: detector ===\n")
    failures, successes = load_events(LOG_FILE)
    flagged = detect_brute_force(failures, successes)
    report(flagged, failures, successes)


if __name__ == "__main__":
    main()
