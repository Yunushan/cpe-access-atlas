# Experimental configuration cryptography

This document describes the implemented offline codec, not approval to import
its output. Exact Türk Telekom H3600P `TTN.10_260210` acceptance, field semantics,
service preservation, and recovery are still unverified.

## Compatibility is security-sensitive

The codec reproduces the vendor-format SHA-256 padding bug and deterministic
key/IV derivation in `config.py`, then uses AES-CBC for type-4 containers.
Changing that derivation, padding, IV policy, or cipher would change the bytes
the target format expects. A new password KDF or authenticated cipher cannot
simply be substituted without a separately supported container format.

The inputs include a device-specific 32-character ASCII encryption passphrase,
serial, and MAC. Serial/MAC values identify the device; do not treat them as
secrets providing independent key entropy. Length/format validation does not
establish passphrase randomness, provenance, or resistance to guessing. Use
only the actual passphrase for an authorized device; the project supplies no
universal key and does not recover or guess it. The SSH login password written
inside the configuration is distinct from this encryption passphrase.

The digest feeds encryption keys and IVs and therefore **is used for security**.
The standard hashlib branch explicitly sets `usedforsecurity=True`. The old
non-security annotation and weak-sensitive-hashing suppression were inaccurate
and have been removed. This does not turn the vendor scheme into a modern
password-hardening design or establish FIPS validation for the custom buggy
digest implementation. Python explains the flag's meaning in its
[hashlib documentation](https://docs.python.org/3/library/hashlib.html).

## Guarantees and non-guarantees

- Type-4 encryption obscures the compressed configuration using the supplied
  key material. Reusing the same device inputs gives the same derived key and
  IV; it is not the fresh-IV design expected for a new general-purpose format.
- CBC does not authenticate a message. CRC checks detect structural corruption,
  but are not a cryptographic MAC, vendor signature, or proof of origin. A
  successful parse or decode/encode round trip does not prove authenticity or
  safe device behavior. PyCryptodome describes these confidentiality-only
  properties for [classic cipher modes](https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html).
- Base64 wrapping, compression, a `.bin` filename, and the container's model
  signature string are not encryption or authenticity controls. Unencrypted
  output contains recoverable credentials and requires explicit CLI consent.
- Owner-only output permissions reduce access by other ordinary local accounts.
  They do not protect against the same account, elevated administrators, an
  untrusted storage provider, or publication of a backup. Secrets also exist
  in process memory; this Python implementation does not promise memory wiping.
- Input size/decompression/XML limits and round-trip checks are defensive
  parsing controls, not a security certification of the vendor format.

Keep originals and generated artifacts in a private, trusted local directory.
Do not upload either encrypted or unencrypted backups to GitHub or a public
issue. Do not rely on encryption to make a configuration export shareable.

## Review and validation still required

Compatibility vectors and synthetic encrypted-output regressions check that
implementation changes preserve the established local behavior. They do not
demonstrate exact-device interoperability, a UID 0 login, WAN isolation, or a
working recovery route. The current codec remains experimental for that reason.

An independent cryptography/security review remains recommended when available,
but is not a mandatory merge or release gate for the solo maintainer. The owner
has accepted retaining this experimental vendor-format compatibility risk;
acceptance is not remediation or proof of safe device behavior. Any scanner
finding about vendor key derivation must be evaluated against this documented
use, not silenced by changing a flag or labeling the data non-sensitive. Do not
claim that removing a suppression resolves the underlying cryptographic risk.
Record the maintainer's assessment and limitations, preserve compatibility test vectors,
and validate exact hardware and recovery separately before making a stable
device-support claim.
