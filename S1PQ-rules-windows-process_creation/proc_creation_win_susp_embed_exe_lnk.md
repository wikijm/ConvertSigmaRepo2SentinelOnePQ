```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="C:\\Windows\\explorer.exe" and tgt.process.image.path="C:\\Windows\\System32\\cmd.exe" and (tgt.process.cmdline contains "powershell" and tgt.process.cmdline contains ".lnk")))
```


# Original Sigma Rule:
```yaml
title: Hidden Powershell in Link File Pattern
id: 30e92f50-bb5a-4884-98b5-d20aa80f3d7a
status: test
description: Detects events that appear when a user click on a link file with a powershell command in it
references:
    - https://www.x86matthew.com/view_post?id=embed_exe_lnk
author: frack113
date: 2022-02-06
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: C:\Windows\explorer.exe
        Image: C:\Windows\System32\cmd.exe
        CommandLine|contains|all:
            - 'powershell'
            - '.lnk'
    condition: selection
falsepositives:
    - Legitimate commands in .lnk files
level: medium
```
