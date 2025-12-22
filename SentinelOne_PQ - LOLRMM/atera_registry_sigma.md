```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SOFTWARE\\ATERA Networks\\AlphaAgent" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\AteraAgent" or registry.keyPath contains "KLM\\SOFTWARE\\WOW6432Node\\Splashtop Inc." or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Splashtop Software Updater" or registry.keyPath contains "HKLM\\SYSTEM\\ControlSet\\Services\\EventLog\\Application\\AlphaAgent" or registry.keyPath contains "HKLM\\SYSTEM\\ControlSet\\Services\\EventLog\\Application\\AteraAgent" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Tracing\\AteraAgent_RASAPI32" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Tracing\\AteraAgent_RASMANCS" or registry.keyPath contains "HKLM\\SOFTWARE\\ATERA Networks\*"))
```


# Original Sigma Rule:
```yaml
title: Potential Atera RMM Tool Registry Activity
id: b69b6b57-5522-4407-8ea1-a74632142f81
status: experimental
description: |
    Detects potential registry activity of Atera RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains:
            - HKLM\SOFTWARE\ATERA Networks\AlphaAgent
            - HKLM\SYSTEM\CurrentControlSet\Services\AteraAgent
            - KLM\SOFTWARE\WOW6432Node\Splashtop Inc.
            - HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop Software Updater
            - HKLM\SYSTEM\ControlSet\Services\EventLog\Application\AlphaAgent
            - HKLM\SYSTEM\ControlSet\Services\EventLog\Application\AteraAgent
            - HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32
            - HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS
            - HKLM\SOFTWARE\ATERA Networks\*
    condition: selection
falsepositives:
    - Legitimate use of Atera
level: medium
```
