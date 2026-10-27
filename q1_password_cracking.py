"""Question 1(a),(b): expected work to crack passwords, with and without salt and dictionary.

Model (Stamp, Section 6.2): work is counted in hash computations, comparisons are free.
  N = 64^10 = 2^60 possible passwords, U = 2^12 users, dictionary D = 2^24 words,
  each user's password is in the dictionary with probability p = 1/8.

A short Monte Carlo simulation at scaled-down sizes checks the closed forms.
"""
from report_output import say
import math
import random

N = 2 ** 60
U = 2 ** 12
D = 2 ** 24
p = 1 / 8


def lg(x):
    return math.log2(x)


say(f"N = 64^10 = 2^{lg(N):.0f}, users U = 2^{lg(U):.0f}, dictionary D = 2^{lg(D):.0f}, p = 1/{round(1/p)}")

# ---------------------------------------------------------------- closed forms
# Case I: one chosen user, brute force. A salt does not matter (Trudy knows Alice's salt).
I_unsalted = I_salted = N / 2

# Case II: one chosen user, dictionary first, then brute force as the fallback.
dict_phase = p * (D / 2) + (1 - p) * D           # hashes spent on the dictionary itself
II = dict_phase + (1 - p) * (N / 2)              # plus brute force when the dictionary fails (7/8 of the time)
II_unsalted = II_salted = II

# Case III: crack ANY password, no dictionary.
# Unsalted: each guess is compared (free) with all U stored hashes, so the first hit comes after N/(U+1) guesses.
III_unsalted = N / (U + 1)
# Salted: a guess is only comparable to one user's hash, so attacking everyone gives no speed-up.
III_salted = N / 2

# Case IV: crack ANY password with the dictionary.
# Unsalted: hash the dictionary once; about U*p users are in it, the first hit appears after D/(U*p + 1) words.
IV_unsalted = D / (U * p + 1)
# Salted: scan the dictionary with each user's salt, one user after another.
# A user fails with prob 1-p (cost D), succeeds with prob p (cost about D/2): (1-p)/p * D + D/2.
IV_salted_exact = (1 - p) / p * D + D / 2
IV_salted_formula = D / p                         # the lab's rule of thumb: dictionary size / probability

rows = [
    ("I   Alice, no dictionary", I_unsalted, I_salted),
    ("II  Alice, with dictionary", II_unsalted, II_salted),
    ("III any user, no dictionary", III_unsalted, III_salted),
    ("IV  any user, with dictionary", IV_unsalted, IV_salted_formula),
]
say(f"\n{'case':32s} {'unsalted':>25s} {'salted':>25s}")
for name, a, b in rows:
    say(f"{name:32s} {a:14.4g} = 2^{lg(a):5.2f} {b:14.4g} = 2^{lg(b):5.2f}")
say(f"\nCase II dictionary phase alone costs {dict_phase:.4g} = 2^{lg(dict_phase):.2f} hashes "
    f"and succeeds only with probability {p}")
say(f"Case IV salted: exact expectation {IV_salted_exact:.4g} = 2^{lg(IV_salted_exact):.2f}, "
    f"rule of thumb D/p = 2^{lg(IV_salted_formula):.0f}")

# ---------------------------------------------------------------- (b) convert Case IV salted into time
say("\n(b) Case IV, salted")
for name, rate in (("fast, 1e10 hash/s", 1e10), ("slow, 1e4 hash/s", 1e4)):
    for label, work in (("D/p = 2^27", IV_salted_formula), ("exact", IV_salted_exact)):
        t = work / rate
        shown = f"{t*1e3:.2f} ms" if t < 1 else (f"{t/3600:.2f} hours" if t < 86400 else f"{t/86400:.2f} days")
        say(f"  {name:18s} {label:10s}: {work:.4g} / {rate:.0e} = {t:.4g} s = {shown}")
say(f"  slowdown from the slow hash: {1e10/1e4:.0e}x")

# ---------------------------------------------------------------- Monte Carlo check at scaled-down sizes
say("\nMonte Carlo check of the closed forms (scaled-down model, 20000 trials each)")
sN, sU, sD, sp = 2 ** 20, 2 ** 8, 2 ** 12, 1 / 8
rng = random.Random(7)
T = 20000


def mc_unsalted_III():
    """Work until the first of sU random passwords is hit, guessing in a random order."""
    return min(rng.randrange(sN) for _ in range(sU)) + 1


def mc_unsalted_IV():
    """Dictionary hashed once; work = position of the first user that is in the dictionary."""
    pos = [rng.randrange(sD) for _ in range(sU) if rng.random() < sp]
    return (min(pos) + 1) if pos else sD


def mc_salted_IV():
    """Scan the dictionary for one user after another until one is cracked."""
    work = 0
    while True:
        if rng.random() < sp:
            return work + rng.randrange(sD) + 1
        work += sD


for name, f, closed in (
    ("III unsalted  N/(U+1)", mc_unsalted_III, sN / (sU + 1)),
    ("IV  unsalted  D/(U*p+1)", mc_unsalted_IV, sD / (sU * sp + 1)),
    ("IV  salted   (1-p)/p*D+D/2", mc_salted_IV, (1 - sp) / sp * sD + sD / 2),
):
    sim = sum(f() for _ in range(T)) / T
    say(f"  {name:26s} formula {closed:9.1f}  simulated {sim:9.1f}  ratio {sim/closed:.3f}")
