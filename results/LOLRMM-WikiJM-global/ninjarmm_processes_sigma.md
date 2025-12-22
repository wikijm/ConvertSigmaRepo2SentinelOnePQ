```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "ninjarmmagent.exe" or src.process.image.path contains "NinjaRMMAgent.exe" or src.process.image.path contains "NinjaRMMAgenPatcher.exe" or src.process.image.path contains "ninjarmm-cli.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential NinjaRMM RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ninjarmmagent.exe
    - NinjaRMMAgent.exe
    - NinjaRMMAgenPatcher.exe
    - ninjarmm-cli.exe
  condition: selection
id: ba65e84e-5ded-409f-9c72-c9704732786d
status: experimental
description: Detects potential processes activity of NinjaRMM RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of NinjaRMM
level: medium
```
