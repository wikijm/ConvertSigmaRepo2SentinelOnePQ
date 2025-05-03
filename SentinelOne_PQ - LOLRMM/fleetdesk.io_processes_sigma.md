```sql
// Translated content (automatically translated on 03-05-2025 01:26:06):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "fleetdeck_agent_svc.exe" or src.process.image.path contains "fleetdeck_commander_svc.exe" or src.process.image.path contains "fleetdeck_installer.exe" or src.process.image.path contains "fleetdeck_agent.exe" or src.process.image.path contains "fleetdeck_commander_launcher.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential FleetDesk.io RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - fleetdeck_agent_svc.exe
    - fleetdeck_commander_svc.exe
    - fleetdeck_installer.exe
    - fleetdeck_agent.exe
    - fleetdeck_commander_launcher.exe
  condition: selection
id: 6d868e41-b759-4e0e-976d-7e3ce05b7b87
status: experimental
description: Detects potential processes activity of FleetDesk.io RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FleetDesk.io
level: medium
```
