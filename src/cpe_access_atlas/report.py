# SPDX-License-Identifier: 0BSD
"""Generate a secret-free hardware research template."""

from __future__ import annotations

from .catalog import Recipe


def build_research_template(recipe: Recipe) -> str:
    next_items = "\n".join(f"- [ ] {item}" for item in recipe.next_evidence)
    return f"""# Sanitized device research report

> Do not paste passwords, configuration exports, packet captures, cookies,
> certificates, serial numbers, MAC addresses, subscriber identifiers, or
> public IP addresses into this report.

## Authorization

- [ ] I own this device, or I have explicit authorization to administer it.
- Ownership: <!-- owned / written authorization / other -->

## Exact target

- Recipe: {recipe.id}
- ISP: {recipe.isp_name}
- Vendor: {recipe.vendor}
- Model: {recipe.model}
- Hardware revision: {recipe.hardware_revision}
- Hardware revision verification: {recipe.hardware_revision_status}
- Firmware: {recipe.firmware}
- Firmware string copied exactly from: <!-- local UI page name only -->
- Private firmware artifact inspected: <!-- yes/no/not available -->
- Private artifact SHA-256: <!-- keep the image private; record hash only -->
- Exact build string found in artifact: <!-- yes/no/not available -->
- Recognized image markers: <!-- high-level names only; no extracted files -->

## Non-secret observations

- Standard local UI reachable: <!-- yes/no -->
- Local UI address: <!-- private IP only -->
- Export/backup button visible: <!-- yes/no -->
- Recovery/reset procedure tested: <!-- yes/no -->
- VoIP/IPTV in use: <!-- yes/no; no credentials -->
- Behavior after factory reset: <!-- high-level description -->

## Evidence still needed

{next_items}

## Outcome

- Access level obtained: <!-- none / privileged web admin / local shell / UID 0 -->
- Exact verification steps:
- Rollback performed:
- Connectivity restored:
- WAN-side management still disabled:

## Sanitization checklist

- [ ] No configuration backup is attached.
- [ ] No secret or credential is present.
- [ ] No serial number, MAC address, certificate, or subscriber ID is present.
- [ ] No public IP address is present.
- [ ] Screenshots have been manually reviewed and redacted.
"""
