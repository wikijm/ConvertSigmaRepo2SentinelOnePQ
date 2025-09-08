```sql
// Translated content (automatically translated on 08-09-2025 01:27:42):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SOFTWARE\\Clients\\Media\\AnyDesk" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\AnyDesk" or registry.keyPath contains "HKLM\\SOFTWARE\\Classes\\.anydesk\\shell\\open\\command" or registry.keyPath contains "HKLM\\SOFTWARE\\Classes\\AnyDesk\\shell\\open\\command" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\AnyDesk Printer\*" or registry.keyPath contains "HKLM\\DRIVERS\\DriverDatabase\\DeviceIds\\USBPRINT\\AnyDesk" or registry.keyPath contains "HKLM\\DRIVERS\\DriverDatabase\\DeviceIds\\WSDPRINT\\AnyDesk" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AnyDesk"))
```


# Original Sigma Rule:
```yaml
title: Potential AnyDesk RMM Tool Registry Activity
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
    - HKLM\SOFTWARE\Clients\Media\AnyDesk
    - HKLM\SYSTEM\CurrentControlSet\Services\AnyDesk
    - HKLM\SOFTWARE\Classes\.anydesk\shell\open\command
    - HKLM\SOFTWARE\Classes\AnyDesk\shell\open\command
    - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\AnyDesk Printer\*
    - HKLM\DRIVERS\DriverDatabase\DeviceIds\USBPRINT\AnyDesk
    - HKLM\DRIVERS\DriverDatabase\DeviceIds\WSDPRINT\AnyDesk
    - HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk
  condition: selection
id: cd914a84-51f3-4342-be98-4e5bc1b7a55e
status: experimental
description: Detects potential registry activity of AnyDesk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of AnyDesk
level: medium
```
