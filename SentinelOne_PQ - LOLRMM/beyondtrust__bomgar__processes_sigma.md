```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*bomgar-scc-*.exe" or src.process.image.path contains "bomgar-scc.exe" or src.process.image.path="*bomgar-pac-*.exe" or src.process.image.path contains "bomgar-pac.exe" or src.process.image.path contains "bomgar-rdp.exe") or (tgt.process.image.path="*bomgar-scc-*.exe" or tgt.process.image.path contains "bomgar-scc.exe" or tgt.process.image.path="*bomgar-pac-*.exe" or tgt.process.image.path contains "bomgar-pac.exe" or tgt.process.image.path contains "bomgar-rdp.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential BeyondTrust (Bomgar) RMM Tool Process Activity
id: 208d9aea-6137-4310-bd7c-2db02f30eb8a
status: experimental
description: |
    Detects potential processes activity of BeyondTrust (Bomgar) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - bomgar-scc-*.exe
            - bomgar-scc.exe
            - bomgar-pac-*.exe
            - bomgar-pac.exe
            - bomgar-rdp.exe
    selection_image:
        Image|endswith:
            - bomgar-scc-*.exe
            - bomgar-scc.exe
            - bomgar-pac-*.exe
            - bomgar-pac.exe
            - bomgar-rdp.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of BeyondTrust (Bomgar)
level: medium
```
