"""Question 3(c): a real-time phishing relay against TOTP versus a passkey (WebAuthn-style, ECDSA P-256).

Trudy runs a look-alike site that forwards everything Alice types to the real site.
The passkey part follows the structure of WebAuthn: the authenticator signs
authenticatorData || SHA-256(clientDataJSON), where clientDataJSON contains the challenge and the
ORIGIN that the browser saw, and authenticatorData contains SHA-256(rpId).
"""
from report_output import say
import base64
import hashlib
import hmac
import json
import secrets
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

REAL_ORIGIN, REAL_RPID = "https://bank.example", "bank.example"
FAKE_ORIGIN, FAKE_RPID = "https://bank-example.evil", "bank-example.evil"
NOW = 1_700_000_000


def hotp(key, counter, digits=6):                    # same algorithm as q3_otp.py (RFC 4226 vectors pass there)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")


class RealSite:
    """The bank: knows the password, the TOTP key and the passkey's PUBLIC key."""

    def __init__(self, password, totp_key, passkey_public):
        self.password, self.totp_key, self.passkey_public = password, totp_key, passkey_public
        self.challenge = None

    def login_password_totp(self, password, code, now):
        return password == self.password and code == hotp(self.totp_key, now // 30)

    def begin_passkey_login(self):
        self.challenge = secrets.token_bytes(32)
        return self.challenge

    def finish_passkey_login(self, auth_data, client_data_json, signature):
        client = json.loads(client_data_json)
        if client["type"] != "webauthn.get" or client["challenge"] != b64(self.challenge):
            return "rejected: wrong type or challenge"
        if client["origin"] != REAL_ORIGIN:
            return f"rejected: origin is {client['origin']}, expected {REAL_ORIGIN}"
        if auth_data[:32] != hashlib.sha256(REAL_RPID.encode()).digest():
            return "rejected: rpIdHash does not match this site"
        signed = auth_data + hashlib.sha256(client_data_json).digest()
        try:
            self.passkey_public.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return "rejected: signature does not verify"
        return "ACCEPTED"


class Authenticator:
    """Alice's phone/security key. Credentials are scoped to the rpId they were created for."""

    def __init__(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.rp_id = REAL_RPID

    def sign(self, rp_id, client_data_json):
        if rp_id != self.rp_id:
            return None                                          # no credential for this site
        auth_data = hashlib.sha256(rp_id.encode()).digest() + b"\x05" + struct.pack(">I", 1)
        sig = self.private.sign(auth_data + hashlib.sha256(client_data_json).digest(), ec.ECDSA(hashes.SHA256()))
        return auth_data, sig


def client_data(challenge, origin):
    return json.dumps({"type": "webauthn.get", "challenge": b64(challenge), "origin": origin}).encode()


password, totp_key = "correct horse battery", secrets.token_bytes(20)
phone = Authenticator()
bank = RealSite(password, totp_key, phone.private.public_key())

say("=== 1. password + TOTP, phished by a real-time relay ===")
alice_code = hotp(totp_key, NOW // 30)                           # Alice reads the code from her app
say("  Alice types password and the 6-digit code on the FAKE site", FAKE_ORIGIN)
say("  the fake site instantly forwards both to the real site (inside the 30 s window)")
say("  real site accepts the relayed login:", bank.login_password_totp(password, alice_code, NOW + 3))

say("\n=== 2. passkey, honest case (Alice on the real site) ===")
chal = bank.begin_passkey_login()
cdj = client_data(chal, REAL_ORIGIN)
auth_data, sig = phone.sign(REAL_RPID, cdj)
say("  real site:", bank.finish_passkey_login(auth_data, cdj, sig))

say("\n=== 3. passkey, Alice is on the FAKE site, Trudy relays the real challenge ===")
chal = bank.begin_passkey_login()
cdj_fake = client_data(chal, FAKE_ORIGIN)                        # the browser writes the origin it really sees
say("  3a. browser asks the authenticator for rpId =", FAKE_RPID)
say("      authenticator returns a signature:", phone.sign(FAKE_RPID, cdj_fake) is not None,
    "(no credential exists for that site)")

say("  3b. worst case: an authenticator signs for the fake site anyway")
auth_fake = hashlib.sha256(FAKE_RPID.encode()).digest() + b"\x05" + struct.pack(">I", 1)
sig_fake = phone.private.sign(auth_fake + hashlib.sha256(cdj_fake).digest(), ec.ECDSA(hashes.SHA256()))
say("      Trudy relays it to the real site ->", bank.finish_passkey_login(auth_fake, cdj_fake, sig_fake))

say("  3c. Trudy edits the origin to the real one to get past the origin check")
cdj_forged = client_data(chal, REAL_ORIGIN)
auth_real_id = hashlib.sha256(REAL_RPID.encode()).digest() + b"\x05" + struct.pack(">I", 1)
say("      real site ->", bank.finish_passkey_login(auth_real_id, cdj_forged, sig_fake))
