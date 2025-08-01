```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains ":\Windows\System32\query.exe" and (tgt.process.cmdline contains "session >" or tgt.process.cmdline contains "process >")))
```


# Original Sigma Rule:
```yaml
title: Query Usage To Exfil Data
id: 53ef0cef-fa24-4f25-a34a-6c72dfa2e6e2
status: test
description: Detects usage of "query.exe" a system binary to exfil information such as "sessions" and "processes" for later use
references:
    - https://twitter.com/MichalKoczwara/status/1553634816016498688
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-01
modified: 2023-01-19
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: ':\Windows\System32\query.exe'
        CommandLine|contains:
            - 'session >'
            - 'process >'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
