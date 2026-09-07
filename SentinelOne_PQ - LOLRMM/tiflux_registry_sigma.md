```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TiService" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TiService\\ImagePath" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TiService\\Start" or registry.keyPath contains "HKLM\\SOFTWARE\\TiFLUX\*" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\TiFLUX\*" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\TiFLUX\\org_id" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\TiAgent" or registry.keyPath contains "HKCU\\SOFTWARE\\TiFlux"))
```


# Original Sigma Rule:
```yaml
title: Potential TiFLUX RMM Tool Registry Activity
id: 22a2b27f-9be6-5bb5-8983-384b197ef013
status: experimental
description: |
    Detects potential registry activity of TiFLUX RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains:
            - 'HKLM\SYSTEM\CurrentControlSet\Services\TiService'
            - 'HKLM\SYSTEM\CurrentControlSet\Services\TiService\ImagePath'
            - 'HKLM\SYSTEM\CurrentControlSet\Services\TiService\Start'
            - 'HKLM\SOFTWARE\TiFLUX\*'
            - 'HKLM\SOFTWARE\WOW6432Node\TiFLUX\*'
            - 'HKLM\SOFTWARE\WOW6432Node\TiFLUX\org_id'
            - 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\TiAgent'
            - 'HKCU\SOFTWARE\TiFlux'
    condition: selection
falsepositives:
    - Legitimate use of TiFLUX
level: medium
```
