```sql
// Translated content (automatically translated on 24-06-2025 01:42:19):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "goverrmc.exe" or src.process.image.path="*govsrv*.exe" or src.process.image.path contains "GovAgentInstallHelper.exe" or src.process.image.path contains "GovAgentx64.exe" or src.process.image.path contains "GovReachClient.exe" or src.process.image.path contains "\GovSrv.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Goverlan RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - goverrmc.exe
    - govsrv*.exe
    - GovAgentInstallHelper.exe
    - GovAgentx64.exe
    - GovReachClient.exe
    - '*\GovSrv.exe'
  condition: selection
id: 2f46ef52-bdef-4473-b391-9ebbea36d547
status: experimental
description: Detects potential processes activity of Goverlan RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Goverlan
level: medium
```
