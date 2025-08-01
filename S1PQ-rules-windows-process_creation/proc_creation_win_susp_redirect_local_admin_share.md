```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains ">" and (tgt.process.cmdline contains "\\127.0.0.1\admin$\" or tgt.process.cmdline contains "\\localhost\admin$\")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Redirection to Local Admin Share
id: ab9e3b40-0c85-4ba1-aede-455d226fd124
status: test
description: Detects a suspicious output redirection to the local admins share, this technique is often found in malicious scripts or hacktool stagers
references:
    - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
    - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
author: Florian Roth (Nextron Systems)
date: 2022-01-16
modified: 2023-12-28
tags:
    - attack.exfiltration
    - attack.t1048
logsource:
    category: process_creation
    product: windows
detection:
    selection_redirect:
        CommandLine|contains: '>'
    selection_share:
        CommandLine|contains:
            - '\\\\127.0.0.1\\admin$\\'
            - '\\\\localhost\\admin$\\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
