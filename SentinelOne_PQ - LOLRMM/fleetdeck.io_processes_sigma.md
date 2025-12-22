```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "fleetdeck_agent_svc.exe" or src.process.image.path contains "fleetdeck_commander_svc.exe" or src.process.image.path contains "fleetdeck_installer.exe" or src.process.image.path contains "fleetdeck_commander_launcher.exe" or src.process.image.path contains "fleetdeck_agent.exe") or (tgt.process.image.path contains "fleetdeck_agent_svc.exe" or tgt.process.image.path contains "fleetdeck_commander_svc.exe" or tgt.process.image.path contains "fleetdeck_installer.exe" or tgt.process.image.path contains "fleetdeck_commander_launcher.exe" or tgt.process.image.path contains "fleetdeck_agent.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential FleetDeck.io RMM Tool Process Activity
id: a0ba751b-8a05-491c-8063-c296a877a803
status: experimental
description: |
    Detects potential processes activity of FleetDeck.io RMM tool
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
            - fleetdeck_agent_svc.exe
            - fleetdeck_commander_svc.exe
            - fleetdeck_installer.exe
            - fleetdeck_commander_launcher.exe
            - fleetdeck_agent.exe
    selection_image:
        Image|endswith:
            - fleetdeck_agent_svc.exe
            - fleetdeck_commander_svc.exe
            - fleetdeck_installer.exe
            - fleetdeck_commander_launcher.exe
            - fleetdeck_agent.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of FleetDeck.io
level: medium
```
