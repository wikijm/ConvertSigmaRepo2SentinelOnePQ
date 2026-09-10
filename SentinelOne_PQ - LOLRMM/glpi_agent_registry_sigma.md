```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SOFTWARE\\GLPI-Agent" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\GLPI-Agent" or registry.keyPath contains "HKLM\\SOFTWARE\\GLPI-Agent\\Installer" or registry.keyPath contains "HKLM\\SOFTWARE\\GLPI-Agent\\Installer\\Version" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\GLPI-Agent\\Installer\\Version" or registry.keyPath contains "HKLM\\SOFTWARE\\GLPI-Agent\\Monitor" or registry.keyPath contains "HKLM\\SOFTWARE\\GLPI-Agent\\server" or registry.keyPath contains "HKLM\\SOFTWARE\\GLPI-Agent\\httpd-port" or registry.keyPath contains "HKLM\\SOFTWARE\\GLPI-Agent\\httpd-ip" or registry.keyPath contains "HKLM\\SOFTWARE\\GLPI-Agent\\httpd-trust" or registry.keyPath contains "HKLM\\SOFTWARE\\GLPI-Agent\\tag" or registry.keyPath contains "HKLM\\SOFTWARE\\GLPI-Agent\\tasks"))
```


# Original Sigma Rule:
```yaml
title: Potential GLPI Agent RMM Tool Registry Activity
id: fc7dd657-c45f-5a75-bb76-dfba8fa8fd69
status: experimental
description: |
    Detects potential registry activity of GLPI Agent RMM tool
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
            - 'HKLM\SOFTWARE\GLPI-Agent'
            - 'HKLM\SOFTWARE\WOW6432Node\GLPI-Agent'
            - 'HKLM\SOFTWARE\GLPI-Agent\Installer'
            - 'HKLM\SOFTWARE\GLPI-Agent\Installer\Version'
            - 'HKLM\SOFTWARE\WOW6432Node\GLPI-Agent\Installer\Version'
            - 'HKLM\SOFTWARE\GLPI-Agent\Monitor'
            - 'HKLM\SOFTWARE\GLPI-Agent\server'
            - 'HKLM\SOFTWARE\GLPI-Agent\httpd-port'
            - 'HKLM\SOFTWARE\GLPI-Agent\httpd-ip'
            - 'HKLM\SOFTWARE\GLPI-Agent\httpd-trust'
            - 'HKLM\SOFTWARE\GLPI-Agent\tag'
            - 'HKLM\SOFTWARE\GLPI-Agent\tasks'
    condition: selection
falsepositives:
    - Legitimate use of GLPI Agent
level: medium
```
