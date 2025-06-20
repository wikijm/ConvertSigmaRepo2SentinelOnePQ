```sql
// Translated content (automatically translated on 21-06-2025 02:03:51):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path contains "C:\Windows \System32\")
```


# Original Sigma Rule:
```yaml
title: TrustedPath UAC Bypass Pattern
id: 4ac47ed3-44c2-4b1f-9d51-bf46e8914126
status: test
description: Detects indicators of a UAC bypass method by mocking directories
references:
    - https://medium.com/tenable-techblog/uac-bypass-by-mocking-trusted-directories-24a96675f6e
    - https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows
    - https://github.com/netero1010/TrustedPath-UACBypass-BOF
author: Florian Roth (Nextron Systems)
date: 2021-08-27
tags:
    - attack.defense-evasion
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: 'C:\Windows \System32\'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
