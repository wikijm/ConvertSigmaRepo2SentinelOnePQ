```sql
// Translated content (automatically translated on 11-06-2025 02:06:45):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\mshta.exe" and (tgt.process.cmdline contains "vbscript" or tgt.process.cmdline contains ".jpg" or tgt.process.cmdline contains ".png" or tgt.process.cmdline contains ".lnk" or tgt.process.cmdline contains ".xls" or tgt.process.cmdline contains ".doc" or tgt.process.cmdline contains ".zip" or tgt.process.cmdline contains ".dll")))
```


# Original Sigma Rule:
```yaml
title: MSHTA Suspicious Execution 01
id: cc7abbd0-762b-41e3-8a26-57ad50d2eea3
status: test
description: Detection for mshta.exe suspicious execution patterns sometimes involving file polyglotism
references:
    - http://blog.sevagas.com/?Hacking-around-HTA-files
    - https://0x00sec.org/t/clientside-exploitation-in-2018-how-pentesting-has-changed/7356
    - https://learn.microsoft.com/en-us/previous-versions/dotnet/framework/data/xml/xslt/xslt-stylesheet-scripting-using-msxsl-script
    - https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997
    - https://twitter.com/mattifestation/status/1326228491302563846
author: Diego Perez (@darkquassar), Markus Neis, Swisscom (Improve Rule)
date: 2019-02-22
modified: 2022-11-07
tags:
    - attack.defense-evasion
    - attack.t1140
    - attack.t1218.005
    - attack.execution
    - attack.t1059.007
    - cve.2020-1599
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\mshta.exe'
        CommandLine|contains:
            - 'vbscript'
            - '.jpg'
            - '.png'
            - '.lnk'
            # - '.chm'  # could be prone to false positives
            - '.xls'
            - '.doc'
            - '.zip'
            - '.dll'
            # - '.exe'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high
```
