```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (((tgt.process.image.path contains "/arp" or tgt.process.image.path contains "/ifconfig" or tgt.process.image.path contains "/netstat" or tgt.process.image.path contains "/networksetup" or tgt.process.image.path contains "/socketfilterfw") or (tgt.process.image.path="/usr/bin/defaults" and (tgt.process.cmdline contains "/Library/Preferences/com.apple.alf" and tgt.process.cmdline contains "read"))) and (not src.process.image.path contains "/wifivelocityd")))
```


# Original Sigma Rule:
```yaml
title: System Network Discovery - macOS
id: 58800443-f9fc-4d55-ae0c-98a3966dfb97
status: test
description: Detects enumeration of local network configuration
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md
author: remotephone, oscd.community
date: 2020-10-06
modified: 2024-08-29
tags:
    - attack.discovery
    - attack.t1016
logsource:
    product: macos
    category: process_creation
detection:
    selection_1:
        Image|endswith:
            - '/arp'
            - '/ifconfig'
            - '/netstat'
            - '/networksetup'
            - '/socketfilterfw'
    selection_2:
        Image: '/usr/bin/defaults'
        CommandLine|contains|all:
            - '/Library/Preferences/com.apple.alf'
            - 'read'
    filter_main_wifivelocityd:
        ParentImage|endswith: '/wifivelocityd'
    condition: 1 of selection_* and not 1 of filter_main_*
falsepositives:
    - Legitimate administration activities
level: informational
```
