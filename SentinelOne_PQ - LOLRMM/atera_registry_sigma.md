```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
event.category="Registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\SOFTWARE\ATERA Networks\AlphaAgent" or registry.keyPath contains "HKLM\SYSTEM\CurrentControlSet\Services\AteraAgent" or registry.keyPath contains "KLM\SOFTWARE\WOW6432Node\Splashtop Inc." or registry.keyPath contains "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop Software Updater" or registry.keyPath contains "HKLM\SYSTEM\ControlSet\Services\EventLog\Application\AlphaAgent" or registry.keyPath contains "HKLM\SYSTEM\ControlSet\Services\EventLog\Application\AteraAgent" or registry.keyPath contains "HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32" or registry.keyPath contains "HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS" or registry.keyPath contains "HKLM\SOFTWARE\ATERA Networks\*"))
```


# Original Sigma Rule:
```yaml
title: Potential Atera RMM Tool Registry Activity
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
    - HKLM\SOFTWARE\ATERA Networks\AlphaAgent
    - HKLM\SYSTEM\CurrentControlSet\Services\AteraAgent
    - KLM\SOFTWARE\WOW6432Node\Splashtop Inc.
    - HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop
      Software Updater
    - HKLM\SYSTEM\ControlSet\Services\EventLog\Application\AlphaAgent
    - HKLM\SYSTEM\ControlSet\Services\EventLog\Application\AteraAgent
    - HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32
    - HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS
    - HKLM\SOFTWARE\ATERA Networks\*
  condition: selection
id: 3d7e3f5a-f6da-4a6d-a65d-11ed0f292c67
status: experimental
description: Detects potential registry activity of Atera RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Atera
level: medium
```
