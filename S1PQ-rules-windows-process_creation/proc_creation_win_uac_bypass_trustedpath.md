```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "C:\Windows \System32\" or tgt.process.image.path contains "C:\Windows \SysWOW64\"))
```


# Original Sigma Rule:
```yaml
title: TrustedPath UAC Bypass Pattern
id: 4ac47ed3-44c2-4b1f-9d51-bf46e8914126
related:
    - id: 0cbe38c0-270c-41d9-ab79-6e5a9a669290
      type: similar
status: test
description: Detects indicators of a UAC bypass method by mocking directories
references:
    - https://medium.com/tenable-techblog/uac-bypass-by-mocking-trusted-directories-24a96675f6e
    - https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows
    - https://github.com/netero1010/TrustedPath-UACBypass-BOF
    - https://x.com/Wietze/status/1933495426952421843
author: Florian Roth (Nextron Systems)
date: 2021-08-27
modified: 2025-06-17
tags:
    - attack.defense-evasion
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - 'C:\Windows \System32\'
            - 'C:\Windows \SysWOW64\'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
