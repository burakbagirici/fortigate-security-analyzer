# Product correctness matrix

All golden inputs under `fixtures/golden/` are synthetic, sanitized, and deterministic.

| Capability | Golden fixture | Positive assertion | Negative assertion |
|---|---|---|---|
| Internet access | `internet_access.conf` | LAN→WAN, outbound, explicit/alias WAN | `ALL` alone does not create a vulnerability claim |
| VIP publishing | `vip_publishing.conf` | VIP resolves; inbound public publishing | Source `all` alone is not called insecure |
| Internal access | `internal_access.conf` | HTTP and custom service resolve | No invented external exposure |
| Zones / SD-WAN | `zones_sdwan.conf` plus VPN-zone tests | Homogeneous LAN/WAN/DMZ/VPN member roles derive safely | Mixed or unresolved roles remain unknown |
| Built-in `any` | `zones_sdwan.conf` | Resolved built-in with unknown role | No unresolved-interface evidence |
| IPsec static context | `ipsec_access.conf` | Phase 1-backed interface resolves as VPN | No live tunnel-state, routing, reachability, or encryption inference |
| Admin security | `admin_exposure.conf` | WAN protocol and trust-host reviews | LAN management excluded; inferred role labeled |
| Security profiles | `profiles.conf` | Custom and built-in profiles resolve | Protected inbound policy has no missing-IPS result |
| ISDB | `isdb.conf` | ID/name/group/custom/source states | No traditional-field integrity false positive or unsafe relationship |
| Multi-VDOM | `multivdom.conf` | Scope-local objects and sequence | No cross-VDOM borrowing or relationship |
| Shadowing | `relationships.conf` | Duplicate/full/conflicting cases | Disabled/schedule/unsupported/ISDB comparisons skipped |
| Integrity | `unresolved.conf` | Real missing references reported | `any`, zones, SD-WAN and predefined ISDB not reported broken |
| Combined modules | `combined_realistic.conf` | Policies, VIP, profiles, DNS/NTP coexist | No missing-profile/integrity false positives |
| Secret suppression | `secrets.conf` | Public structures remain usable | Fake secrets absent from parser, analysis, health and UI structures |
| Malformed input | Inline golden cases | No unhandled exception | No invented policy facts or confident findings |
