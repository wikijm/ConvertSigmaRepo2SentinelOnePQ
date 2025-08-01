```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\w3wp.exe" or src.process.image.path contains "\w3wp.exe") and (tgt.process.cmdline contains "&ipconfig&echo" or tgt.process.cmdline contains "&quser&echo" or tgt.process.cmdline contains "&whoami&echo" or tgt.process.cmdline contains "&c:&echo" or tgt.process.cmdline contains "&cd&echo" or tgt.process.cmdline contains "&dir&echo" or tgt.process.cmdline contains "&echo [E]" or tgt.process.cmdline contains "&echo [S]")))
```


# Original Sigma Rule:
```yaml
title: Chopper Webshell Process Pattern
id: fa3c117a-bc0d-416e-a31b-0c0e80653efb
status: test
description: Detects patterns found in process executions cause by China Chopper like tiny (ASPX) webshells
references:
    - https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/
author: Florian Roth (Nextron Systems), MSTI (query)
date: 2022-10-01
tags:
    - attack.persistence
    - attack.discovery
    - attack.t1505.003
    - attack.t1018
    - attack.t1033
    - attack.t1087
logsource:
    category: process_creation
    product: windows
detection:
    selection_origin:
        - Image|endswith: '\w3wp.exe'
        - ParentImage|endswith: '\w3wp.exe'
    selection_cmdline:
        CommandLine|contains:
            - '&ipconfig&echo'
            - '&quser&echo'
            - '&whoami&echo'
            - '&c:&echo'
            - '&cd&echo'
            - '&dir&echo'
            - '&echo [E]'
            - '&echo [S]'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
