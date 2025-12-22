```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "paexec.exe" or src.process.image.path="*PAExec-*.exe" or src.process.image.path contains "remcom.exe" or src.process.image.path contains "remcomsvc.exe" or src.process.image.path contains "xcmd.exe" or src.process.image.path contains "xcmdsvc.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential PSEXEC (Clone) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - paexec.exe
    - PAExec-*.exe
    - remcom.exe
    - remcomsvc.exe
    - xcmd.exe
    - xcmdsvc.exe
  condition: selection
id: ce875247-1a7a-4679-8fdd-23736f66fbf7
status: experimental
description: Detects potential processes activity of PSEXEC (Clone) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of PSEXEC (Clone)
level: medium
```
