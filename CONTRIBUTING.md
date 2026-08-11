# Contributing

Thank you for helping document owner-authorized access to ISP-provided
equipment.

## Device recipe requirements

A recipe contribution must include:

1. ISP, vendor, exact model, hardware revision, and exact firmware string.
2. The access level obtained: privileged web administration, local root shell,
   configuration recovery, or another precisely defined capability.
3. Sanitized evidence showing the method and rollback path.
4. Confirmation that WAN-side administration remains disabled.
5. Test results on the exact device and firmware.
6. A statement that the contributor owns the device or had authorization.

Do not include secrets, configuration exports, subscriber data, arbitrary
shell payloads, firmware images, or vendor-owned binaries.

## Status progression

- `researching`: evidence is incomplete or the known method is patched.
- `experimental`: implemented but not independently reproduced.
- `verified`: reproduced on the exact device and firmware with rollback.
- `stable`: independently reproduced and maintained across releases.
- `blocked`: a known technical blocker prevents the requested access.

`verified` and `stable` require hardware evidence. Mock tests alone are not
enough.

## Development

Use Python 3.11 or newer:

```shell
python -m pip install -e .
python -m unittest discover -s tests -v
cpe-atlas validate
```

All contributions are licensed under 0BSD. Add SPDX identifiers to new source
files and sign off commits with the Developer Certificate of Origin:

```text
Signed-off-by: Your Name <you@example.com>
```
