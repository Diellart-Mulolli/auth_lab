"""Question 2: fingerprint reader error rates, thresholds and identification."""
from report_output import say
import math

thresholds = [40, 50, 60, 70, 80]
far = {40: 1e-2, 50: 2e-3, 60: 4e-4, 70: 5e-5, 80: 1e-6}   # fraud rate: impostor accepted
frr = {40: 1e-4, 50: 5e-4, 60: 2e-3, 70: 1e-2, 80: 5e-2}   # insult rate: legitimate user rejected

say("(a) equal error rate")
say("  threshold   FAR        FRR        FAR - FRR")
for t in thresholds:
    say(f"  {t:>6d}   {far[t]:.0e}   {frr[t]:.0e}   {far[t]-frr[t]:+.2e}")
for a, b in zip(thresholds, thresholds[1:]):
    if (far[a] - frr[a]) * (far[b] - frr[b]) < 0:
        lo, hi = a, b
say(f"  FAR - FRR changes sign between thresholds {lo} and {hi}")

# linear interpolation of both curves between lo and hi
d_far = (far[hi] - far[lo]) / (hi - lo)
d_frr = (frr[hi] - frr[lo]) / (hi - lo)
t_eer = lo + (frr[lo] - far[lo]) / (d_far - d_frr)
eer = far[lo] + d_far * (t_eer - lo)
say(f"  linear interpolation: FAR(t) = {far[lo]:.0e} + ({d_far:.3e})(t-{lo}), "
    f"FRR(t) = {frr[lo]:.0e} + ({d_frr:.3e})(t-{lo})")
say(f"  crossing at t = {t_eer:.2f}, EER = {eer:.4e}")

# cross-check: interpolate log10 of the rates (the rates change by orders of magnitude)
lf = lambda d, t: math.log10(d[t])
u = (lf(frr, lo) - lf(far, lo)) / ((lf(far, hi) - lf(far, lo)) - (lf(frr, hi) - lf(frr, lo)))
t_log = lo + u * (hi - lo)
eer_log = 10 ** (lf(far, lo) + u * (lf(far, hi) - lf(far, lo)))
say(f"  cross-check, log-linear interpolation: t = {t_log:.2f}, EER = {eer_log:.4e}")
say(f"  typical published EER 2e-3: this reader is {2e-3/eer:.2f}x better (linear estimate)")

say("\n(b) building with 2,000 employees, 4 entries per day")
entries = 2000 * 4
say(f"  legitimate entries per day = {entries}")
for t in (50, 60, 70):
    say(f"  threshold {t}: rejected per day = {entries} x {frr[t]:.0e} = {entries*frr[t]:.1f}"
        f"   (one rejection per {1/frr[t]:.0f} entries)")
for t in (50, 60, 70):
    p10 = 1 - (1 - far[t]) ** 10
    say(f"  threshold {t}: P(impostor accepted within 10 tries) = 1-(1-{far[t]:.0e})^10 = {p10:.4%}")

say("\n(c) identification against N = 100,000 templates")
N = 100_000
for t in (70, 80):
    p_exact = 1 - (1 - far[t]) ** N
    p_approx = 1 - math.exp(-N * far[t])
    say(f"  threshold {t}: expected false matches N*FAR = {N*far[t]:.3g}; "
        f"P(at least one) exact = {p_exact:.5f}, approx 1-exp(-N*FAR) = {p_approx:.5f}")
need = -math.log(1 - 0.01) / N
say(f"  FAR needed for P(false match) <= 1% over N: {need:.2e} (vs 1:1 authentication FAR of 1e-4..1e-3)")
