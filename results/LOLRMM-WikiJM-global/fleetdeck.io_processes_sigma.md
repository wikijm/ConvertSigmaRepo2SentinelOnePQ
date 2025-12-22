```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "fleetdeck_agent_svc.exe" or src.process.image.path contains "fleetdeck_commander_svc.exe" or src.process.image.path contains "fleetdeck_installer.exe" or src.process.image.path contains "fleetdeck_commander_launcher.exe" or src.process.image.path contains "fleetdeck_agent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential FleetDeck.io RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - fleetdeck_agent_svc.exe
    - fleetdeck_commander_svc.exe
    - fleetdeck_installer.exe
    - fleetdeck_commander_launcher.exe
    - fleetdeck_agent.exe
  condition: selection
id: 945182ec-fda2-4f02-a77e-aa649bc311b6
status: experimental
description: Detects potential processes activity of FleetDeck.io RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FleetDeck.io
level: medium
```
