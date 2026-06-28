# bruteforcelab

A self-contained Python lab covering the full credential-attack pipeline: **attack → defense → detection**. No network calls, no real accounts, no external dependencies — everything runs locally with the Python standard library.

## Files

| File | Description |
|------|-------------|
| `bruteforcelab.py` | Attack and defense demonstrations |
| `wordlist.txt` | 10 common passwords used in the dictionary attack |
| `auth.log` | Realistic sample SSH auth log with a brute-force pattern embedded |
| `detector.py` | Log parser that detects brute-force IPs using a sliding time window |

---

## Stage 1 — Attack

`bruteforcelab.py` demonstrates two attack techniques against locally generated password hashes:

1. **Dictionary attack** — hashes each word in `wordlist.txt` and compares against a target hash. Shows how fast weak, reused passwords fall.
2. **Brute force** — exhausts every combination in a character set up to a given length. Cracks a 4-digit PIN to illustrate how small keyspaces are trivially searchable.

```bash
python3 bruteforcelab.py
```

---

## Stage 2 — Defense

The same script then shows what stops those attacks:

3. **Slow salted hashing (PBKDF2)** — each guess costs ~54ms instead of ~0.000001ms for raw SHA-256, making large-scale offline cracking impractical.
4. **Rate limiting / account lockout** — simulates an online login that locks after 5 failed attempts, blocking automated guessing entirely.

---

## Stage 3 — Detection

`detector.py` reads `auth.log` and flags any IP that exceeds a threshold of failed login attempts within a sliding time window. It also reports whether the attack ultimately succeeded.

```bash
python3 detector.py
```

### Detection logic

- **Sliding window**: for each failed login from a given IP, count how many other failures from that IP fall within `WINDOW_MINUTES` (default: 5 min). If the peak count crosses `THRESHOLD` (default: 5), the IP is flagged.
- **Outcome tracking**: checks whether a flagged IP ever achieved a successful login, indicating the attack worked.

### Sample output

```
=== bruteforcelab: detector ===

[!] Brute-force detection results (threshold: 5 failures within 5 min)

  ALERT: 203.0.113.42
    Failed attempts : 14 total, 13 within 5-minute window
    Attack outcome  : SUCCEEDED — attacker gained access!
    Time range      : 09:15:03 – 09:35:21
```

---

## Key takeaways

| Layer | Technique | What it shows |
|-------|-----------|---------------|
| Attack | Dictionary attack | Common passwords fall in milliseconds |
| Attack | Brute force | Short keyspaces (PINs) are exhausted trivially |
| Defense | PBKDF2 key stretching | Makes each offline guess ~54,000x slower |
| Defense | Account lockout | Stops online guessing after N attempts |
| Detection | Sliding-window log analysis | Catches brute-force patterns before they succeed |
