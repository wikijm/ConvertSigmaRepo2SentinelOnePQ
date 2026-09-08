```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\FSAgentService" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\FreshServiceScan" or registry.keyPath contains "HKLM\\SOFTWARE\\Freshdesk\\FSAgent" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\Freshdesk\\FSAgent" or registry.keyPath contains "HKLM\\SOFTWARE\\Freshworks\\FreshServiceProbe" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\Freshworks\\FreshServiceProbe" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\FreshService Probe" or registry.keyPath contains "HKLM\\SOFTWARE\\FreshService Probe" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{8BE075F9-36C7-4145-8BC0-35D420223576}" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{892D2C60-AFC1-48C0-8C5D-A2DC856A3605}"))
```


# Original Sigma Rule:
```yaml
title: Potential Freshservice RMM Tool Registry Activity
id: bafddb72-d7ab-5bab-933c-e1dc71fbaa1a
status: experimental
description: |
    Detects potential registry activity of Freshservice RMM tool
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
            - 'HKLM\SYSTEM\CurrentControlSet\Services\FSAgentService'
            - 'HKLM\SYSTEM\CurrentControlSet\Services\FreshServiceScan'
            - 'HKLM\SOFTWARE\Freshdesk\FSAgent'
            - 'HKLM\SOFTWARE\WOW6432Node\Freshdesk\FSAgent'
            - 'HKLM\SOFTWARE\Freshworks\FreshServiceProbe'
            - 'HKLM\SOFTWARE\WOW6432Node\Freshworks\FreshServiceProbe'
            - 'HKLM\SOFTWARE\Microsoft\FreshService Probe'
            - 'HKLM\SOFTWARE\FreshService Probe'
            - 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{8BE075F9-36C7-4145-8BC0-35D420223576}'
            - 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{892D2C60-AFC1-48C0-8C5D-A2DC856A3605}'
    condition: selection
falsepositives:
    - Legitimate use of Freshservice
level: medium
```
