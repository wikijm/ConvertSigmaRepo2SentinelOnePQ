```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\cscript.exe") and (tgt.process.cmdline contains ":\\Temp\\" or tgt.process.cmdline contains ":\\Tmp\\" or tgt.process.cmdline contains ":\\Users\\Public\\" or tgt.process.cmdline contains ":\\Windows\\Temp\\" or tgt.process.cmdline contains "\\AppData\\Local\\Temp\\") and (tgt.process.cmdline contains ".js" or tgt.process.cmdline contains ".jse" or tgt.process.cmdline contains ".vba" or tgt.process.cmdline contains ".vbe" or tgt.process.cmdline contains ".vbs" or tgt.process.cmdline contains ".wsf")))
```


# Original Sigma Rule:
```yaml
title: Potential Dropper Script Execution Via WScript/CScript
id: cea72823-df4d-4567-950c-0b579eaf0846
related:
    - id: 1e33157c-53b1-41ad-bbcc-780b80b58288
      type: similar
status: test
description: Detects wscript/cscript executions of scripts located in user directories
references:
    - https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
    - https://redcanary.com/blog/gootloader/
author: Margaritis Dimitrios (idea), Florian Roth (Nextron Systems), oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2019-01-16
modified: 2024-01-30
tags:
    - attack.execution
    - attack.t1059.005
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_exec:
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
    selection_paths:
        CommandLine|contains:
            - ':\Temp\'
            - ':\Tmp\'
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - '\AppData\Local\Temp\'
    selection_ext:
        CommandLine|contains:
            - '.js'
            - '.jse'
            - '.vba'
            - '.vbe'
            - '.vbs'
            - '.wsf'
    condition: all of selection_*
falsepositives:
    - Some installers might generate a similar behavior. An initial baseline is required
level: medium
```
