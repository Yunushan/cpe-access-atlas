# Architecture

CPE Access Atlas separates facts about a device from code that may eventually
change it.

```text
CLI
 ├── provider and recipe catalog
 ├── exact firmware matcher
 ├── single-private-host policy
 ├── non-mutating diagnostics
 └── fail-closed apply gate
```

## Design rules

1. **Exact matching.** ISP, model, hardware revision, and firmware are distinct
   compatibility dimensions. A recipe for one firmware is never substituted
   for another.
2. **Typed access levels.** Privileged web administration, a local shell, UID 0,
   and bootloader access are not interchangeable.
3. **No arbitrary recipe code.** Catalog JSON is data, not shell or Python.
4. **Local-only policy.** Diagnostic network operations accept one RFC1918 or
   IPv6 ULA literal. Hostnames, ranges, CIDRs, and target lists are rejected.
5. **No discovery or guessing.** The project does not scan a LAN, enumerate
   remote devices, or try passwords.
6. **Plan before mutation.** Version 0.1.0 includes no mutating adapter. The
   `apply` entry point exists to demonstrate and test the refusal path.
7. **Evidence before status.** Hardware verification and recovery evidence are
   required before a recipe can become verified.

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
