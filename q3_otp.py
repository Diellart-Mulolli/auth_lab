"""Question 3(a),(b): challenge-response, HOTP/TOTP, and online guessing of 6-digit codes.

HOTP (RFC 4226) and TOTP (RFC 6238) are implemented from scratch with HMAC-SHA-1 (the
construction from the hash lab) and checked against the RFC test vectors.
"""
from report_output import say
import hashlib
import hmac
import math
import secrets
import struct


def hotp(key, counter, digits=6):
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F                                   # dynamic truncation
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10 ** digits).zfill(digits)


def totp(key, t, digits=6, step=30):
    return hotp(key, t // step, digits)


# ---------------------------------------------------------------- validate against the RFCs
K_RFC = b"12345678901234567890"
rfc4226 = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
ok4226 = all(hotp(K_RFC, c) == v for c, v in enumerate(rfc4226))
say(f"RFC 4226 Appendix D, HOTP counters 0..9 (key '12345678901234567890'): "
    f"{'all 10 vectors match' if ok4226 else 'MISMATCH'}")
say("  computed:", " ".join(hotp(K_RFC, c) for c in range(10)))

rfc6238 = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
           1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130"}
ok6238 = all(totp(K_RFC, t, digits=8) == v for t, v in rfc6238.items())
say(f"RFC 6238 Appendix B, TOTP-SHA1, 8 digits: {'all 6 vectors match' if ok6238 else 'MISMATCH'}")
for t, v in rfc6238.items():
    say(f"  t = {t:>11d}  T = {t//30:>9d}  code = {totp(K_RFC, t, digits=8)}")

# ---------------------------------------------------------------- (a) challenge-response and replay
say("\n(a) challenge-response: h(K, R), K shared with Bob, R chosen by Bob")
K = secrets.token_bytes(20)
resp = lambda k, r: hmac.new(k, r, hashlib.sha256).hexdigest()
R1 = secrets.token_bytes(16)
recorded = (R1, resp(K, R1))                 # Trudy records one run of the protocol
say(f"  Bob sends random R1; Alice's phone answers; Trudy records the pair (R1, response)")
say(f"  later, Bob again sends R1 (reused):   Trudy replays -> accepted: {recorded[1] == resp(K, R1)}")
R2 = secrets.token_bytes(16)
say(f"  later, Bob sends a fresh R2:          Trudy replays -> accepted: {recorded[1] == resp(K, R2)}")

say("\nTOTP counter and time of the next code")
t = 1_700_000_000
T = t // 30
nxt = (T + 1) * 30
say(f"  t = {t}: T = floor({t}/30) = {T}   (exact quotient {t/30:.4f})")
say(f"  the next code appears at (T+1)*30 = {T+1} * 30 = {nxt}, i.e. {nxt - t} s later")
say(f"  example 6-digit TOTP at t={t} with the RFC test key: {totp(K_RFC, t)}  "
    f"(and {totp(K_RFC, nxt)} at t={nxt})")

# ---------------------------------------------------------------- (b) guessing 6-digit codes
say("\n(b) Trudy knows the password and guesses 6-digit TOTP codes (3 attempts per 30 s, no lockout)")
SPACE = 10 ** 6
windows = 24 * 3600 // 30
say(f"  windows in 24 h = 86400/30 = {windows}")


def p_hit(valid_codes, attempts):
    """P(at least one of `attempts` distinct guesses equals one of `valid_codes` random codes), exact."""
    return 1 - math.comb(SPACE - valid_codes, attempts) / math.comb(SPACE, attempts)


for label, valid in (("current window only", 1), ("previous + current + next window", 3)):
    p_win = p_hit(valid, 3)
    p_day = 1 - (1 - p_win) ** windows
    mean_days = (1 / p_win) * 30 / 86400
    say(f"  {label:34s}: P(success per window) = {p_win:.4e}; P(success in 24 h) = "
        f"1-(1-{p_win:.3e})^{windows} = {p_day:.4%}; expected time to success = {mean_days:.0f} days")

say("\n  NIST SP 800-63B-4, Sec. 3.2.2: at most 100 consecutive failed attempts, then the authenticator is disabled")
for label, valid in (("current window only", 1), ("previous + current + next window", 3)):
    p_guess = valid / SPACE
    p100 = 1 - (1 - p_guess) ** 100
    say(f"  {label:34s}: 100 guesses -> P(success) = {p100:.4%}")
