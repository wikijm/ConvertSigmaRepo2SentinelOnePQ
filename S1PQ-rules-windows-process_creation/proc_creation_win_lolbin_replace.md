```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\replace.exe" and (tgt.process.cmdline contains "-a" or tgt.process.cmdline contains "/a" or tgt.process.cmdline contains "–a" or tgt.process.cmdline contains "—a" or tgt.process.cmdline contains "―a")))
```


# Original Sigma Rule:
```yaml
title: Replace.exe Usage
id: 9292293b-8496-4715-9db6-37028dcda4b3
status: test
description: Detects the use of Replace.exe which can be used to replace file with another file
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Replace/
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/replace
author: frack113
date: 2022-03-06
modified: 2024-03-13
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\replace.exe'
    argument:
        CommandLine|contains|windash: '-a'
    condition: selection and argument
falsepositives:
    - Unknown
level: medium
```
