```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "ir_agent.exe" or src.process.image.path contains "rapid7_agent_core.exe" or src.process.image.path contains "rapid7_endpoint_broker.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Rapid7 RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ir_agent.exe
    - rapid7_agent_core.exe
    - rapid7_endpoint_broker.exe
  condition: selection
id: 020a798c-246d-45fb-85bf-5df3be0cbf06
status: experimental
description: Detects potential processes activity of Rapid7 RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Rapid7
level: medium
```
