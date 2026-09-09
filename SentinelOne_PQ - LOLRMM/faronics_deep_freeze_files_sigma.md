```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\Faronics\\Deep Freeze\\DFServ.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Faronics\\Deep Freeze\\DFServEx.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Faronics\\Deep Freeze\\DFWks.exe" or tgt.file.path contains "C:\\Windows\\Temp\\DFServiceInit.log" or tgt.file.path contains "C:\\Users\\<USER>\\AppData\\Local\\Temp\\_$Df\\DFStdInstall.sib"))
```


# Original Sigma Rule:
```yaml
title: Potential Faronics Deep Freeze RMM Tool File Activity
id: 8033796a-9b9b-5ebe-97f3-0fe87e17bd83
status: experimental
description: |
    Detects potential files activity of Faronics Deep Freeze RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files (x86)\Faronics\Deep Freeze\DFServ.exe'
            - 'C:\Program Files (x86)\Faronics\Deep Freeze\DFServEx.exe'
            - 'C:\Program Files (x86)\Faronics\Deep Freeze\DFWks.exe'
            - 'C:\Windows\Temp\DFServiceInit.log'
            - 'C:\Users\<USER>\AppData\Local\Temp\_$Df\DFStdInstall.sib'
    condition: selection
falsepositives:
    - Legitimate use of Faronics Deep Freeze
level: medium
```
