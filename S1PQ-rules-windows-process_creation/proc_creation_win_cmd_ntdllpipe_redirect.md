```sql
// Translated content (automatically translated on 22-07-2025 02:21:01):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "type %windir%\system32\ntdll.dll" or tgt.process.cmdline contains "type %systemroot%\system32\ntdll.dll" or tgt.process.cmdline contains "type c:\windows\system32\ntdll.dll" or tgt.process.cmdline contains "\ntdll.dll > \\.\pipe\"))
```


# Original Sigma Rule:
```yaml
title: NtdllPipe Like Activity Execution
id: bbc865e4-7fcd-45a6-8ff1-95ced28ec5b2
status: test
description: Detects command that type the content of ntdll.dll to a different file or a pipe in order to evade AV / EDR detection. As seen being used in the POC NtdllPipe
references:
    - https://web.archive.org/web/20220306121156/https://www.x86matthew.com/view_post?id=ntdll_pipe
author: Florian Roth (Nextron Systems)
date: 2022-03-05
modified: 2023-03-07
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'type %windir%\system32\ntdll.dll'
            - 'type %systemroot%\system32\ntdll.dll'
            - 'type c:\windows\system32\ntdll.dll'
            - '\\ntdll.dll > \\\\.\\pipe\\'
    condition: selection
falsepositives:
    - Unknown
level: high
```
