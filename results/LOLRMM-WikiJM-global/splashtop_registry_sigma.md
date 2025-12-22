```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "KLM\\SOFTWARE\\WOW6432Node\\Splashtop Inc.\*" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Splashtop Software Updater" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SplashtopRemoteService" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Splashtop-Splashtop Streamer-Remote Session/Operational" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Splashtop-Splashtop Streamer-Status/Operational" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Splashtop Software Updater\\InstallRefCount" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\SplashtopRemoteService" or registry.keyPath contains "HKU\\.DEFAULT\\Software\\Splashtop Inc.\*" or registry.keyPath contains "HKU\\SID\\Software\\Splashtop Inc.\*" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\Splashtop PDF Remote Printer" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\Splashtop Inc.\\Splashtop Remote Server\\ClientInfo\*"))
```


# Original Sigma Rule:
```yaml
title: Potential Splashtop RMM Tool Registry Activity
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
    - KLM\SOFTWARE\WOW6432Node\Splashtop Inc.\*
    - HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop
      Software Updater
    - HKLM\SYSTEM\CurrentControlSet\Services\SplashtopRemoteService
    - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop
      Streamer-Remote Session/Operational
    - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop
      Streamer-Status/Operational
    - HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop
      Software Updater\InstallRefCount
    - HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\SplashtopRemoteService
    - HKU\.DEFAULT\Software\Splashtop Inc.\*
    - HKU\SID\Software\Splashtop Inc.\*
    - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\Splashtop PDF
      Remote Printer
    - HKLM\SOFTWARE\WOW6432Node\Splashtop Inc.\Splashtop Remote Server\ClientInfo\*
  condition: selection
id: 04c91c15-0a2e-4092-8417-e011178ae756
status: experimental
description: Detects potential registry activity of Splashtop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Splashtop
level: medium
```
