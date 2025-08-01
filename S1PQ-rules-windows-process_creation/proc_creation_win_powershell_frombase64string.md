```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "::FromBase64String(")
```


# Original Sigma Rule:
```yaml
title: Base64 Encoded PowerShell Command Detected
id: e32d4572-9826-4738-b651-95fa63747e8a
status: test
description: Detects usage of the "FromBase64String" function in the commandline which is used to decode a base64 encoded string
references:
    - https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639
author: Florian Roth (Nextron Systems)
date: 2020-01-29
modified: 2023-01-26
tags:
    - attack.t1027
    - attack.defense-evasion
    - attack.execution
    - attack.t1140
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '::FromBase64String('
    condition: selection
falsepositives:
    - Administrative script libraries
level: high
```
