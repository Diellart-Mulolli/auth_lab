"""Question 5: Bell-LaPadula with compartments, Biba, covert-channel timing, and inference control."""
from report_output import say
import random

# ---------------------------------------------------------------- (a) Bell-LaPadula with compartments
LEVEL = {"Unclassified": 0, "Confidential": 1, "Secret": 2, "Top Secret": 3}
ABBR = {"U": "Unclassified", "C": "Confidential", "S": "Secret", "TS": "Top Secret"}


def label(level, comps):
    return (LEVEL[ABBR[level]], frozenset(comps))


def dominates(a, b):
    """(L1, C1) dominates (L2, C2) iff L1 >= L2 and C1 is a superset of C2."""
    return a[0] >= b[0] and a[1] >= b[1]


subjects = {"Alice": label("TS", {"Cat"}), "Bob": label("S", {"Cat", "Dog"}),
            "Carol": label("S", set()), "Dave": label("C", set())}
objects = {"O1": label("S", {"Cat"}), "O2": label("TS", set()), "O3": label("C", {"Dog"}),
           "O4": label("U", set()), "O5": label("S", {"Cat", "Dog"})}


def show(lab):
    name = {v: k for k, v in LEVEL.items()}[lab[0]]
    return f"({name}, {{{', '.join(sorted(lab[1]))}}})"


def blp(subject, op, obj):
    s, o = subjects[subject], objects[obj]
    if op == "read":
        ok = dominates(s, o)
        rule = "simple security property (no read up)"
        why = "subject dominates object" if ok else (
            "object level is higher" if o[0] > s[0] else "subject lacks compartment(s) " + str(sorted(o[1] - s[1])))
    else:
        ok = dominates(o, s)
        rule = "*-property (no write down)"
        why = "object dominates subject" if ok else (
            "object level is lower" if o[0] < s[0] else "object lacks compartment(s) " + str(sorted(s[1] - o[1])))
    return ok, rule, why


say("(a) Bell-LaPadula with compartments")
for n, l in subjects.items():
    say(f"  subject {n:6s} {show(l)}")
for n, l in objects.items():
    say(f"  object  {n:6s} {show(l)}")
requests = [("Alice", "read", "O1"), ("Alice", "read", "O5"), ("Alice", "write", "O4"), ("Bob", "read", "O5"),
            ("Bob", "write", "O3"), ("Carol", "write", "O2"), ("Carol", "read", "O1"), ("Dave", "read", "O3")]
say("  requests:")
for i, (s, op, o) in enumerate(requests, 1):
    ok, rule, why = blp(s, op, o)
    say(f"   ({i}) {s:5s} {op:5s} {o}: {'ALLOWED' if ok else 'DENIED '}  {rule}; {why}")
writers = [s for s in subjects if blp(s, "write", "O1")[0]]
say(f"  subjects that may write to O1 {show(objects['O1'])}: {writers}")
say(f"  of these, who may also read O1: {[s for s in writers if blp(s, 'read', 'O1')[0]]}  (blind write-up)")

# ---------------------------------------------------------------- (b) Biba
say("\n(b) Biba integrity")
I = {"Low": 0, "Medium": 1, "High": 2}
procs = {"installer": "High", "editor": "Medium", "browser": "Low"}
objs = {"OS files": "High", "config file": "Medium", "downloaded file": "Low"}
can_write = lambda lvl, o: I[objs[o]] <= I[lvl]          # no write up
can_read = lambda lvl, o: I[lvl] <= I[objs[o]]           # no read down
say(f"  browser (Low) writes OS files (High):       {can_write(procs['browser'], 'OS files')}")
say(f"  installer (High) reads downloaded file (Low): {can_read(procs['installer'], 'downloaded file')}  (strict Biba: no read down)")
lvl = procs["installer"]
say("  low water mark: installer reads the downloaded file")
lvl_after = min((lvl, "Low"), key=lambda x: I[x])
say(f"    I(installer) := min(High, Low) = {lvl_after}")
for when, l in (("before", lvl), ("after ", lvl_after)):
    say(f"    {when}: installer may write {[o for o in objs if can_write(l, o)]}")

# ---------------------------------------------------------------- (c) covert channel
say("\n(c) covert channel at the DoD limit of 1 bit/s")
for name, bits in (("256-bit AES key", 256), ("3072-bit RSA private exponent", 3072), ("1 MiB document", 8 * 2 ** 20)):
    s = bits / 1.0
    human = f"{s:.0f} s = {s/60:.1f} min" if s < 3600 else (f"{s/3600:.1f} hours" if s < 86400 else f"{s/86400:.1f} days")
    say(f"  {name:32s}: {bits:>9d} bits -> {human}")

# ---------------------------------------------------------------- (d) inference
say("\n(d) inference against 'at least 5 records' query-set-size control")
n1, avg1, n2, avg2 = 20, 8.10, 19, 8.00
sum1, sum2 = n1 * avg1, n2 * avg2
say(f"  Query 1: {n1} students, average {avg1}  -> sum = {sum1:.1f}")
say(f"  Query 2: {n2} students, average {avg2}  -> sum = {sum2:.1f}")
say(f"  both sets have at least 5 members, so both are answered")
say(f"  difference: {n1} - {n2} = {n1-n2} student(s) from Gjilan, with grade {sum1:.1f} - {sum2:.1f} = {sum1-sum2:.1f}")
say(f"  asked directly, 'students from Gjilan' (size {n1-n2}) would have been refused: {n1-n2} < 5")

say("\nbetter defence: add calibrated Laplace noise (differential privacy, epsilon = 1)")
rng = random.Random(2026)
lap = lambda scale: rng.expovariate(1 / scale) - rng.expovariate(1 / scale)    # Laplace(0, scale)
sens = 10.0                                      # one grade lies in [0, 10], so one student changes a sum by at most 10
noisy1, noisy2 = sum1 + lap(sens / 1.0), sum2 + lap(sens / 1.0)
say(f"  noisy sums: {noisy1:.1f} and {noisy2:.1f}; noisy difference = {noisy1-noisy2:.1f} (true value {sum1-sum2:.1f})")
errs = [abs(lap(sens) - lap(sens)) for _ in range(20000)]
say(f"  typical error of the difference over 20000 repetitions: {sum(errs)/len(errs):.1f} grade points "
    f"(the grade itself is at most 10), so the individual grade is hidden")
