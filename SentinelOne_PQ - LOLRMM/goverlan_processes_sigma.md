```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "goverrmc.exe" or src.process.image.path="*govsrv*.exe" or src.process.image.path contains "GovAgentInstallHelper.exe" or src.process.image.path contains "GovAgentx64.exe" or src.process.image.path contains "GovReachClient.exe" or src.process.image.path contains "GovSrv.exe") or (tgt.process.image.path contains "goverrmc.exe" or tgt.process.image.path="*govsrv*.exe" or tgt.process.image.path contains "GovAgentInstallHelper.exe" or tgt.process.image.path contains "GovAgentx64.exe" or tgt.process.image.path contains "GovReachClient.exe" or tgt.process.image.path contains "GovSrv.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Goverlan RMM Tool Process Activity
id: 615e510c-87dd-4294-92e0-7776b858589e
status: experimental
description: |
    Detects potential processes activity of Goverlan RMM tool
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
            - goverrmc.exe
            - govsrv*.exe
            - GovAgentInstallHelper.exe
            - GovAgentx64.exe
            - GovReachClient.exe
            - GovSrv.exe
    selection_image:
        Image|endswith:
            - goverrmc.exe
            - govsrv*.exe
            - GovAgentInstallHelper.exe
            - GovAgentx64.exe
            - GovReachClient.exe
            - GovSrv.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Goverlan
level: medium
```
