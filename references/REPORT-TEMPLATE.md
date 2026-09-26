# Threat report — template

Vendor-neutral. Fill every section. Attach or link the raw artifacts (tarballs, VSIXes, `gh api` dumps, deobfuscated stages) referenced by the report.

---

## 1. Summary

*One paragraph. What is the sample, where was it found, what does it do, who is the likely operator, what's the recommended action?*

## 2. Sample identifiers

| Field | Value |
|---|---|
| Package / repo / VSIX name | |
| Version(s) affected | |
| Ecosystem (npm / PyPI / GitHub / VS Code / other) | |
| First seen | |
| Sample SHA-256 (tarball / VSIX / commit) | |
| Registry / marketplace URL | |
| Cache mirror URL(s) (jsDelivr, unpkg, PyPI Simple) | |

## 3. Attack surface & delivery

*How does a victim end up running this? Typosquat? Dep confusion? Lure repo? Marketplace update? Compromised maintainer?*

## 4. Execution

*What happens on first run / install / open / activation? Include command-line output snippets, activation events, install hooks.*

## 5. Payload

*Walk each stage. For each stage: what it does, what it drops, what C2 it talks to, what obfuscation it uses.*

## 6. Persistence

*Any scheduled task, cron, LaunchAgent, autorun key, IDE task, git hook?*

## 7. Exfiltration

*What data leaves the host? Where does it go? Include full URLs, IPs, ports, protocols.*

## 8. IOCs

### Hostnames / IPs
```
```

### Wallets (chain: address)
```
```

### Packages / VSIXes / repos
```
```

### Accounts (registry / GitHub / marketplace)
```
```

### File hashes
```
```

### Campaign markers
```
```

## 9. Attribution

*Fill this from `ATTRIBUTION-CHECKLIST.md`. Include your Yes-answer count and the confidence level (attributed / attributable / unattributed).*

## 10. Detection & response

*Detection rules / hunt queries a defender should run. Response steps for compromised hosts.*

## 11. References

*Every source you used, hyperlinked. Include your own prior work and other researchers' work.*

## 12. Disclosure

*Have you notified: the affected registry? the maintainer? the community threat DB? the affected downstream projects? Include timestamps.*

---

*Report author, date, contact.*
