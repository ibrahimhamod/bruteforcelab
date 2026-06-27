import hashlib
import itertools
import string
import time
import secrets

# ============================================================
# bruteforcelab — a self-contained lab for studying credential
# attacks and the defenses that stop them. Nothing here touches
# any real system or network. Every "target" is generated locally.
# ============================================================


def sha256(text):
    """Fast, UNSALTED hash — intentionally weak, to show why it fails."""
    return hashlib.sha256(text.encode()).hexdigest()


# ---- The "victim" account, created locally just for this lab ----
SECRET_PASSWORD = "hunter2"             # pretend this is the real password
TARGET_HASH = sha256(SECRET_PASSWORD)   # this is all an attacker would see


def dictionary_attack(target_hash, wordlist_path):
    """Try every word in a list. This is how most real cracks happen:
    people reuse common, weak passwords."""
    start = time.time()
    with open(wordlist_path) as f:
        for line in f:
            guess = line.strip()
            if sha256(guess) == target_hash:
                elapsed = time.time() - start
                print(f"[+] CRACKED: '{guess}' in {elapsed:.4f}s")
                return guess
    print("[-] Not found in wordlist")
    return None


def brute_force_attack(target_hash, charset, max_len):
    """Try every combination up to max_len. Shows how the keyspace
    explodes as password length grows."""
    start = time.time()
    attempts = 0
    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            guess = "".join(combo)
            attempts += 1
            if sha256(guess) == target_hash:
                elapsed = time.time() - start
                print(f"[+] CRACKED: '{guess}' after {attempts} tries in {elapsed:.4f}s")
                return guess
    print(f"[-] Exhausted {attempts} combinations, not found")
    return None


# ============================================================
# DEFENSES — why the attacks above stop working
# ============================================================

def slow_hash(password, salt, rounds=200_000):
    """Salted + key-stretched hash (PBKDF2). Each guess now costs real
    time, so offline brute force becomes impractical."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds).hex()


class RateLimiter:
    """Simulates account lockout, the main defense against ONLINE brute
    force. After N wrong tries, the account locks."""
    def __init__(self, max_attempts=5):
        self.max_attempts = max_attempts
        self.failures = 0
        self.locked = False

    def attempt(self, guess, real_password):
        if self.locked:
            print("[LOCKED] Account locked. Try again later.")
            return False
        if guess == real_password:
            print("[OK] Login success")
            self.failures = 0
            return True
        self.failures += 1
        print(f"[X] Wrong password ({self.failures}/{self.max_attempts})")
        if self.failures >= self.max_attempts:
            self.locked = True
            print("[LOCKED] Too many attempts, account locked.")
        return False


def main():
    print("=== bruteforcelab ===\n")

    print("[1] Dictionary attack on a weak, unsalted hash")
    dictionary_attack(TARGET_HASH, "wordlist.txt")

    print("\n[2] Brute force on a short 4-digit PIN")
    pin = "0427"
    pin_hash = sha256(pin)
    brute_force_attack(pin_hash, string.digits, 4)

    print("\n[3] Defense: slow salted hashing (PBKDF2)")
    salt = secrets.token_bytes(16)
    start = time.time()
    slow_hash("hunter2", salt)
    per_guess = time.time() - start
    print(f"    One PBKDF2 guess takes ~{per_guess:.4f}s (vs ~0.000001s for SHA-256)")
    print("    Multiply that across millions of guesses and brute force dies.")

    print("\n[4] Defense: rate limiting / account lockout")
    limiter = RateLimiter(max_attempts=5)
    for guess in ["1234", "password", "letmein", "admin", "qwerty", "hunter2"]:
        limiter.attempt(guess, "hunter2")


if __name__ == "__main__":
    main()
