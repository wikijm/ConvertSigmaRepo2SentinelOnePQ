```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "ConsoleHost_history.txt" or tgt.process.cmdline contains "(Get-PSReadLineOption).HistorySavePath"))
```


# Original Sigma Rule:
```yaml
title: Potential PowerShell Console History Access Attempt via History File
id: f4ff7323-b5fc-4323-8b52-6b9408e15788
status: experimental
description: |
    Detects potential access attempts to the PowerShell console history directly via history file (ConsoleHost_history.txt).
    This can give access to plaintext passwords used in PowerShell commands or used for general reconnaissance.
references:
    - https://0xdf.gitlab.io/2018/11/08/powershell-history-file.html
author: Luc Génaux
date: 2025-04-03
tags:
    - attack.credential-access
    - attack.t1552.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'ConsoleHost_history.txt'
            - '(Get-PSReadLineOption).HistorySavePath'
    condition: selection
falsepositives:
    - Legitimate access of the console history file is possible
level: medium
```
