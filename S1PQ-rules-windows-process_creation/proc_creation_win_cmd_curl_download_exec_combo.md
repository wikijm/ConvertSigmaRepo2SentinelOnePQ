```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains " -c " or tgt.process.cmdline contains " /c " or tgt.process.cmdline contains " –c " or tgt.process.cmdline contains " —c " or tgt.process.cmdline contains " ―c ") and (tgt.process.cmdline contains "curl " and tgt.process.cmdline contains "http" and tgt.process.cmdline contains "-o" and tgt.process.cmdline contains "&")))
```


# Original Sigma Rule:
```yaml
title: Curl Download And Execute Combination
id: 21dd6d38-2b18-4453-9404-a0fe4a0cc288
status: test
description: Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.
references:
    - https://medium.com/@reegun/curl-exe-is-the-new-rundll32-exe-lolbin-3f79c5f35983 # Dead Link
author: Sreeman, Nasreddine Bencherchali (Nextron Systems)
date: 2020-01-13
modified: 2024-03-05
tags:
    - attack.defense-evasion
    - attack.t1218
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|windash: ' -c '
        CommandLine|contains|all:
            - 'curl '
            - 'http'
            - '-o'
            - '&'
    condition: selection
falsepositives:
    - Unknown
level: high
```
