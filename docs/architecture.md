# Architecture

CPE Access Atlas separates facts about a device from code that may eventually
change it.

```text
CLI
 ├── provider and recipe catalog
 ├── exact firmware matcher
 ├── single-private-host policy
 ├── non-mutating diagnostics
 ├── sanitized offline UART-log inspection
 ├── offline private-config inspection and generation
 └── fail-closed apply gate
```

## Design rules

1. **Exact matching.** ISP, model, hardware revision, and firmware are required
   compatibility dimensions. A recipe for one hardware revision or firmware is
   never substituted for another. Hardware records separately declare whether
   the revision is `exact` or still `unresolved`.
2. **Typed access levels.** Privileged web administration, a local shell, UID 0,
   and bootloader access are not interchangeable.
3. **No arbitrary recipe code.** Catalog JSON is data, not shell or Python.
4. **Local-only policy.** Diagnostic network operations accept one RFC1918 or
   IPv6 ULA literal. Hostnames, ranges, CIDRs, and target lists are rejected.
5. **No discovery or guessing.** The project does not scan a LAN, enumerate
   remote devices, or try passwords.
6. **Plan before mutation.** This release includes no mutating adapter. The
   `apply` entry point exists to demonstrate and test the refusal path.
7. **Schema before load.** Bundled JSON is validated against packaged JSON
   Schemas before it is converted into typed records.
8. **Evidence before status.** Hardware verification and recovery evidence are
   required before a recipe can become verified; unresolved hardware records
   remain non-mutating research records.
9. **Offline config boundaries.** The configuration codec reads and writes only
   user-supplied local artifacts. It never connects to, flashes, or changes a
   device, and generated SSH fields are not evidence of a root shell. Private
   outputs are written atomically with owner-only POSIX modes or a protected
   Windows ACL for the creating account. Windows creates the restrictive ACL
   with the file, then verifies its owner, sole explicit access grant, and
   persistent-filesystem ACL support through the open handle before writing.
   Parent-directory grants are not inherited. The directory must nevertheless
   remain private and under the user's control; same-account access, elevated
   administrators, and untrusted storage providers are outside this protection.
   The CLI does not print credential-bearing configuration or redaction output.
   `config-generate` additionally requires an explicit
   `--acknowledge-unverified-compatibility` opt-in whenever the selected recipe
   is not verified/stable or its hardware revision is not exact. That opt-in
   records acceptance of the compatibility risk; it never enables device I/O.
   Encrypted output additionally requires
   `--acknowledge-legacy-crypto`, because the vendor-compatible format uses
   legacy SHA-256 derivation and unauthenticated CBC. A baseline and its output
   may not be the same path, even with replacement explicitly requested.
   The separate `private-protect`/`private-unprotect` commands provide an
   authenticated local-at-rest container using scrypt and AES-GCM; that format
   is intentionally not accepted by a modem and is not a publishing or
   compatibility mechanism.
10. **UART evidence is input-only.** `uart-evidence` reads one bounded local
    capture, extracts allow-listed boot metadata, and emits no raw lines,
    device identity values, or credentials. It never opens a serial port or
    treats an observed prompt as verified bootloader or root access.

On POSIX, private output checks that the parent directory supports `fsync`
before creating a temporary file, flushes the file before publication, and
synchronizes the directory after publication and removal of the temporary
name. Unsupported synchronization and flush failures are reported; a target
already published before a later failure is retained, so a failed call can
still leave a complete output file. These operations request durability from
the OS and filesystem; they are not a tested physical power-loss guarantee.
Windows retains its existing file flush and atomic publication behavior,
without a directory-durability claim. Filesystem and hardware behavior still
matter; see the [Linux `fsync` documentation](https://man7.org/linux/man-pages/man2/fsync.2.html)
and [Apple's storage-cache limitations](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html).

The experimental codec reproduces vendor key derivation and AES-CBC container
behavior; it is not a general-purpose secure backup format. See the
[configuration cryptography threat model](config-cryptography.md) for the
security-sensitive compatibility constraint and unresolved validation limits.

## Future adapter contract

A future mutating adapter must:

- require ownership acknowledgement;
- prove an exact device and firmware match;
- require a successful, protected backup or documented recovery path;
- show the complete plan and obtain a second confirmation;
- use a user-supplied unique credential without logging it;
- verify the requested access independently;
- verify that WAN-side management was not enabled;
- provide rollback and interruption handling;
- remain unavailable from public or multi-target addresses.

Adapters must never execute arbitrary commands embedded in catalog files.
