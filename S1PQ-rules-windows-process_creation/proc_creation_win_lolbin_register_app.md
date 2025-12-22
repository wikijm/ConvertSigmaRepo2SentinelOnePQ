```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\\register_app.vbs" and tgt.process.cmdline contains "-register"))
```


# Original Sigma Rule:
```yaml
title: REGISTER_APP.VBS Proxy Execution
id: 1c8774a0-44d4-4db0-91f8-e792359c70bd
status: test
description: Detects the use of a Microsoft signed script 'REGISTER_APP.VBS' to register a VSS/VDS Provider as a COM+ application.
references:
    - https://twitter.com/sblmsrsn/status/1456613494783160325?s=20
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-19
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\register_app.vbs'
            - '-register'
    condition: selection
falsepositives:
    - Legitimate usage of the script. Always investigate what's being registered to confirm if it's benign
level: medium
```
