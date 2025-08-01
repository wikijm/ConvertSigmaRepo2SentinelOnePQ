```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "\Event Viewer\RecentViews" or tgt.process.cmdline contains "\EventV~1\RecentViews") and tgt.process.cmdline contains ">"))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Using Event Viewer RecentViews
id: 30fc8de7-d833-40c4-96b6-28319fbc4f6c
related:
    - id: 63e4f530-65dc-49cc-8f80-ccfa95c69d43
      type: similar
status: test
description: Detects the pattern of UAC Bypass using Event Viewer RecentViews
references:
    - https://twitter.com/orange_8361/status/1518970259868626944
    - https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/#execute
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-11-22
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection_path:
        # Example: ysoserial.exe -o raw -f BinaryFormatter - g DataSet -c calc > RecentViews & copy RecentViews %LOCALAPPDATA%\Microsoft\EventV~1\RecentViews & eventvwr.exe
        CommandLine|contains:
            - '\Event Viewer\RecentViews'
            - '\EventV~1\RecentViews'
    selection_redirect:
        CommandLine|contains: '>'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
