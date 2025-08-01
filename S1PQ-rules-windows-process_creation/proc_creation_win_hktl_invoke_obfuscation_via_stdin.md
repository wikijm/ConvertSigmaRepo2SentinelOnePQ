```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline matches "(?i)(set).*&&\\s?set.*(environment|invoke|\\$\\{?input).*&&.*"")
```


# Original Sigma Rule:
```yaml
title: Invoke-Obfuscation Via Stdin
id: 9c14c9fa-1a63-4a64-8e57-d19280559490
status: test
description: Detects Obfuscated Powershell via Stdin in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task28)
author: Nikita Nazarov, oscd.community
date: 2020-10-12
modified: 2024-04-16
tags:
    - attack.defense-evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|re: '(?i)(set).*&&\s?set.*(environment|invoke|\$\{?input).*&&.*"'
    condition: selection
falsepositives:
    - Unknown
level: high
```
