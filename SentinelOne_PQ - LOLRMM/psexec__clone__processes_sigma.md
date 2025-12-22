```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "paexec.exe" or src.process.image.path="*PAExec-*.exe" or src.process.image.path contains "remcom.exe" or src.process.image.path contains "remcomsvc.exe" or src.process.image.path contains "xcmd.exe" or src.process.image.path contains "xcmdsvc.exe") or (tgt.process.image.path contains "paexec.exe" or tgt.process.image.path="*PAExec-*.exe" or tgt.process.image.path contains "remcom.exe" or tgt.process.image.path contains "remcomsvc.exe" or tgt.process.image.path contains "xcmd.exe" or tgt.process.image.path contains "xcmdsvc.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential PSEXEC (Clone) RMM Tool Process Activity
id: 598933f0-cccc-4996-9706-b5664854dbed
status: experimental
description: |
    Detects potential processes activity of PSEXEC (Clone) RMM tool
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
            - paexec.exe
            - PAExec-*.exe
            - remcom.exe
            - remcomsvc.exe
            - xcmd.exe
            - xcmdsvc.exe
    selection_image:
        Image|endswith:
            - paexec.exe
            - PAExec-*.exe
            - remcom.exe
            - remcomsvc.exe
            - xcmd.exe
            - xcmdsvc.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of PSEXEC (Clone)
level: medium
```
