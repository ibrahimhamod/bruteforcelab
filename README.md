# bruteforcelab

A self-contained Python lab for studying how credential attacks work and what defenses stop them. No network calls, no real accounts — everything runs locally.

## Files

| File | Description |
|------|-------------|
| `bruteforcelab.py` | Main lab script |
| `wordlist.txt` | 10 common passwords used in the dictionary attack demo |

## What it demonstrates

### Attacks
1. **Dictionary attack** — hashes each word in `wordlist.txt` and compares against the target hash. Shows how fast weak, reused passwords fall.
2. **Brute force** — exhausts every combination in a character set up to a given length. Cracks a 4-digit PIN to show how small keyspaces are trivially searchable.

### Defenses
3. **Slow salted hashing (PBKDF2)** — each guess costs ~54ms instead of ~0.000001ms, making large-scale offline cracking impractical.
4. **Rate limiting / account lockout** — simulates an online login that locks after 5 failed attempts, blocking automated guessing.

## Usage

```bash
python3 bruteforcelab.py
```

No dependencies beyond the Python standard library.

## Sample output

```
=== bruteforcelab ===

[1] Dictionary attack on a weak, unsalted hash
[+] CRACKED: 'hunter2' in 0.0001s

[2] Brute force on a short 4-digit PIN
[+] CRACKED: '0427' after 1538 tries in 0.0007s

[3] Defense: slow salted hashing (PBKDF2)
    One PBKDF2 guess takes ~0.0525s (vs ~0.000001s for SHA-256)
    Multiply that across millions of guesses and brute force dies.

[4] Defense: rate limiting / account lockout
[X] Wrong password (1/5)
[X] Wrong password (2/5)
[X] Wrong password (3/5)
[X] Wrong password (4/5)
[X] Wrong password (5/5)
[LOCKED] Too many attempts, account locked.
[LOCKED] Account locked. Try again later.
```

## Key takeaways

- Unsalted fast hashes (MD5, SHA-256) are crackable in milliseconds with a wordlist
- Short PINs have tiny keyspaces — 4 digits = 10,000 combinations
- PBKDF2/bcrypt/argon2 make each offline guess orders of magnitude slower
- Account lockout is the primary defense against online brute force
