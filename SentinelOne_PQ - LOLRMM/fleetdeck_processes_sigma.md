```sql
// Translated content (automatically translated on 01-05-2025 01:43:46):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "fleetdeck_agent_svc.exe")
```


# Original Sigma Rule:
```yaml
title: Potential FleetDeck RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - fleetdeck_agent_svc.exe
  condition: selection
id: b8194fd9-f7a9-4c15-97cd-34351971c00b
status: experimental
description: Detects potential processes activity of FleetDeck RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FleetDeck
level: medium
```
