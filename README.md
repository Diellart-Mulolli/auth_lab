# Authentication and Authorization Lab – Python scripts and report

**Course:** Information Security, *Authentication and Authorization in Practice* lab
**Author:** Diellart Mulolli (230756200035)
**Repository:** <https://github.com/Diellart-Mulolli/auth_lab>

This repository contains the lab report (`report.tex` / `report.pdf`) and six Python scripts. The
scripts verify the calculations and simulations in the report. Their exact output is printed in
Appendix A of the report.

| Script | Report section | What it shows |
|---|---|---|
| `q1_password_cracking.py` | Question 1(a),(b) | Expected work to crack passwords with/without salt and dictionary, plus a Monte Carlo check |
| `q2_biometrics.py` | Question 2(a)–(c) | Equal error rate by interpolation, daily rejections, identification false matches |
| `q3_otp.py` | Question 3(a),(b) | HOTP/TOTP from scratch (checked against the RFC test vectors), challenge replay, guessing odds |
| `q3_phishing.py` | Question 3(c) | A real-time phishing relay against TOTP versus a passkey (ECDSA P-256) |
| `q4_access_control.py` | Question 4 | ACL and C-list from the matrix, policy checks, the confused deputy, RBAC counts |
| `q5_mls.py` | Question 5 | Bell–LaPadula with compartments, Biba, covert-channel times, an inference attack |

## Project structure

```
auth_lab/
├── .gitignore                 keeps virtual environments, Python caches and LaTeX build files out of git
├── README.md                  this file: running guide and explanation of every script
├── requirements.txt           Python dependency (cryptography, used only by q3_phishing.py)
├── report.tex                 LaTeX source of the report (IEEE references, pdfLaTeX/Overleaf/Tectonic)
├── report.pdf                 compiled report, 16 pages (Appendix A: script values and outputs)
├── report_output.py           small helper shared by the scripts: print() that wraps long lines
├── q1_password_cracking.py    Q1: password-cracking work, salt, dictionary, Monte Carlo check
├── q2_biometrics.py           Q2: FAR/FRR, EER, building and identification scenarios
├── q3_otp.py                  Q3a,b: HOTP/TOTP, replay, online guessing of 6-digit codes
├── q3_phishing.py             Q3c: phishing relay against TOTP vs a passkey
├── q4_access_control.py       Q4: access control matrix, confused deputy, RBAC
└── q5_mls.py                  Q5: Bell–LaPadula, Biba, covert channel, inference control
```

---

## Running guide

### 1. Prerequisites

| Requirement | Needed for | Check with |
|---|---|---|
| Python 3.8 or newer | all scripts | `python3 --version` |
| `cryptography` ≥ 41 | `q3_phishing.py` only | `python3 -c "import cryptography; print(cryptography.__version__)"` |

Five of the six scripts use only the Python standard library and run on any Python 3.8+
installation without installing anything.

### 2. Get the project and set up (once)

Download it from GitHub (*Code → Download ZIP*) or clone it:

```bash
git clone https://github.com/Diellart-Mulolli/auth_lab.git
```
```bash
cd auth_lab
```

To run `q3_phishing.py`, install its one dependency, preferably in a virtual environment:

```bash
python3 -m venv .venv
```
```bash
source .venv/bin/activate
```
```bash
pip install -r requirements.txt
```

On Windows, use `py -m venv .venv`, then `.venv\Scripts\activate`, then the same `pip` command.
Run `deactivate` when you are done.

### 3. Run the scripts

Run each script from inside the project folder (on Windows, write `py` instead of `python3`).

| Command | Runtime* | What to look for in the output |
|---|---|---|
| `python3 q1_password_cracking.py` | ≈ 3 s | table with `2^59.00`, `2^48.00`, `2^15.00`, `2^27.00`; `13.42 ms` and `3.73 hours`; simulation ratios close to `1.000` |
| `python3 q2_biometrics.py` | < 0.1 s | `crossing at t = 54.84, EER = 1.2258e-03`; `rejected per day = ... = 16.0`; `P(at least one) exact = 0.99326` |
| `python3 q3_otp.py` | < 0.1 s | `all 10 vectors match`, `all 6 vectors match`; `T = ... = 56666666`; `P(success in 24 h) = ... 0.8603%` |
| `python3 q3_phishing.py` | < 0.1 s | the relayed TOTP login `True`, the passkey relay `rejected` in 3a, 3b and 3c |
| `python3 q4_access_control.py` | < 0.1 s | `via the service: allowed GradingService wrote GradeDB`, then the capability version `DENIED` |
| `python3 q5_mls.py` | < 0.1 s | the eight `ALLOWED`/`DENIED` decisions; `97.1 days`; `grade 162.0 - 152.0 = 10.0` |

\*Measured on the author's laptop. `q1` takes longest because of its Monte Carlo simulation.

Every script is deterministic: the simulations use fixed random seeds, and `q3_otp.py`/`q3_phishing.py`
print only values that do not depend on their random keys, so the output is identical on every run.

### 4. Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'cryptography'` | Only `q3_phishing.py` needs it: activate the virtual environment, or run `pip install -r requirements.txt`. |
| `ModuleNotFoundError: No module named 'report_output'` | Run the scripts from inside the project folder, next to `report_output.py`. |
| `python3: command not found` (Windows) | Use `py` or `python` instead. |
| A `SyntaxError` on an f-string or `math.comb` error | Your Python is older than 3.8; upgrade it. |

### 5. Suggested live demo for the presentation

`python3 q3_phishing.py` is the clearest demo: the same relay that steals a password + TOTP login is
rejected three times when the victim uses a passkey. `python3 q4_access_control.py` shows the confused
deputy destroying the grade database, and the capability version refusing the same request.

---

## 1. `q1_password_cracking.py` – the math of password cracking (Question 1)

Parameters: `N = 64^10 = 2^60` passwords, `U = 2^12` users, dictionary `D = 2^24`, probability `p = 1/8`.

```
case                                              unsalted                    salted
I   Alice, no dictionary              5.765e+17 = 2^59.00      5.765e+17 = 2^59.00
II  Alice, with dictionary            5.044e+17 = 2^58.81      5.044e+17 = 2^58.81
III any user, no dictionary           2.814e+14 = 2^48.00      5.765e+17 = 2^59.00
IV  any user, with dictionary          3.27e+04 = 2^15.00      1.342e+08 = 2^27.00
```

**What it means.** Without salt, one guess is compared with all `2^12` stored hashes for free, so Case III drops
from `2^59` to `2^48`, and Case IV is only `2^15` guesses. A per-user salt removes that parallelism (`2^59` and
`2^27`). But `2^27` hashes still take only 13 ms at 10^10 hashes/s: a salt cannot make a guessable password strong.
A slow memory-hard hash (10^4 hashes/s) raises Case IV to 3.7 hours. Case II barely changes because Alice is
one chosen victim who is outside the dictionary 7 times out of 8. The Monte Carlo lines at the bottom
simulate the same model at small sizes and agree with the closed forms within 2%.

## 2. `q2_biometrics.py` – biometric error rates (Question 2)

Uses the vendor table of FAR/FRR per threshold.

```
FAR - FRR changes sign between thresholds 50 and 60
crossing at t = 54.84, EER = 1.2258e-03
threshold 70: expected false matches N*FAR = 5; P(at least one) exact = 0.99326
```

**What it means.** FAR falls and FRR rises as the threshold grows; they cross between 50 and 60 at an EER of
about 1.2·10^-3 (better than the typical published 2·10^-3). For a door used 8000 times a day, threshold 70 gives
80 rejections but only 0.05% for an impostor with 10 tries and meets NIST's FMR ≤ 1/10 000. Identification
against 100 000 templates multiplies the error by N: at threshold 70 a false match is almost certain (99.3%), so
identification needs a far lower FAR than authentication.

## 3. `q3_otp.py` – one-time codes (Question 3(a),(b))

Implements HOTP (RFC 4226) and TOTP (RFC 6238) with HMAC-SHA-1 and checks them against the RFC test vectors.

```
RFC 4226 Appendix D, HOTP counters 0..9 (key '12345678901234567890'): all 10 vectors match
RFC 6238 Appendix B, TOTP-SHA1, 8 digits: all 6 vectors match
t = 1700000000: T = floor(1700000000/30) = 56666666   (exact quotient 56666666.6667)
the next code appears at (T+1)*30 = 56666667 * 30 = 1700000010, i.e. 10 s later
```

**What it means.** All 16 official test vectors match, so the implementation is correct. The challenge-response
demo shows why `R` must never repeat: a recorded answer is accepted again when the same `R` is reused and rejected for
a fresh `R`. Guessing 6-digit codes with 3 tries per 30 s succeeds with 0.86% in 24 h (2.56% if the previous and
next window are also accepted); NIST SP 800-63B-4 limits consecutive failures to 100, which caps the
probability at 0.01%–0.03%.

## 4. `q3_phishing.py` – phishing a TOTP login versus a passkey (Question 3(c))

Simulates a bank, a look-alike site and a passkey: the authenticator signs
`authenticatorData ‖ SHA-256(clientDataJSON)` with ECDSA P-256, where `clientDataJSON` contains the challenge and the
origin the browser saw.

```
real site accepts the relayed login: True            (password + TOTP)
3a. authenticator returns a signature: False         (no credential for the fake site)
3b. ... -> rejected: origin is https://bank-example.evil, expected https://bank.example
3c. ... -> rejected: signature does not verify       (origin rewritten by the attacker)
```

**What it means.** A password and a TOTP code are typed by a human and are not bound to a website, so a
real-time relay works. A passkey's signature is bound to the origin: the credential is not offered on the fake
domain, a signature made for the fake origin is rejected by the real site, and the origin cannot be rewritten
without invalidating the signature.

## 5. `q4_access_control.py` – matrix, confused deputy, RBAC (Question 4)

```
GradeDB: Besnik: rw, Drita: rw, Ermal: r, GradingService: rw
direct attack:    DENIED  Arta may not write GradeDB
via the service:  allowed GradingService wrote GradeDB
capability version, Arta asks for the grade database:      DENIED  Arta holds no capability named 'grade_db'
```

**What it means.** Stored by column the matrix is an ACL, by row a C-list. The checks list five problems (a service
that changes grades and writes the log, a TA with write access to final grades, no ownership, a student who cannot
read her own grade, an overwritable log). The simulation shows the confused deputy: Arta has no rights on the grade
database, but the service checks *its own* rights and overwrites it. With capabilities the user must hand over a
handle she holds, so she cannot name the grade database. RBAC shrinks 5250 matrix cells to 15 role cells plus
1050 assignments.

## 6. `q5_mls.py` – multilevel security, covert channels, inference (Question 5)

```
(2) Alice read  O5: DENIED   simple security property (no read up); subject lacks compartment(s) ['Dog']
(6) Carol write O2: ALLOWED  *-property (no write down); object dominates subject
subjects that may write to O1 (Secret, {Cat}): ['Carol', 'Dave']
1 MiB document                  :   8388608 bits -> 97.1 days
difference: 20 - 19 = 1 student(s) from Gjilan, with grade 162.0 - 152.0 = 10.0
```

**What it means.** A label dominates another if its level is at least as high *and* its compartments are a
superset; Bell–LaPadula allows reading down and writing up. Biba is the opposite for integrity, and the low water
mark lowers a process's integrity after it reads untrusted data. At 1 bit/s a 256-bit key leaks in 4.3 minutes. The
two permitted queries differ by one student, so subtracting them reveals that student's grade; noise calibrated to
the sensitivity (differential privacy) hides it.

---

## Building the PDF

`report.pdf` is already compiled. To rebuild it after editing `report.tex`:

- **Overleaf (no installation):** upload `report.tex` and click *Recompile* (pdfLaTeX works).
- **Tectonic** (single binary, downloads only what it needs):
  ```bash
  tectonic report.tex
  ```
- **TeX Live:** run pdfLaTeX twice so the citation numbers resolve:
  ```bash
  pdflatex report.tex && pdflatex report.tex
  ```
