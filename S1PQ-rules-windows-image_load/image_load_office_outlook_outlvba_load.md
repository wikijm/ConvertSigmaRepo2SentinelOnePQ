```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (src.process.image.path contains "\\outlook.exe" and module.path contains "\\outlvba.dll"))
```


# Original Sigma Rule:
```yaml
title: Microsoft VBA For Outlook Addin Loaded Via Outlook
id: 9a0b8719-cd3c-4f0a-90de-765a4cb3f5ed
status: test
description: Detects outlvba (Microsoft VBA for Outlook Addin) DLL being loaded by the outlook process
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=58
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-08
modified: 2024-03-12
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\outlook.exe'
        ImageLoaded|endswith: '\outlvba.dll'
    condition: selection
falsepositives:
    - Legitimate macro usage. Add the appropriate filter according to your environment
level: medium
```
