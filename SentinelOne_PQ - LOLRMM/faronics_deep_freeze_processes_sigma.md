```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\DFServ.exe" or src.process.image.path contains "\\DFServEx.exe" or src.process.image.path contains "\\DFWks.exe" or src.process.image.path contains "\\DFC.exe" or src.process.image.path contains "\\DFStd.exe" or src.process.image.path contains "\\DFStdInstall.exe" or src.process.image.path contains "\\CloudWksInstall.exe" or src.process.image.path contains "\\DFInst.exe") or (tgt.process.image.path contains "\\DFServ.exe" or tgt.process.image.path contains "\\DFServEx.exe" or tgt.process.image.path contains "\\DFWks.exe" or tgt.process.image.path contains "\\DFC.exe" or tgt.process.image.path contains "\\DFStd.exe" or tgt.process.image.path contains "\\DFStdInstall.exe" or tgt.process.image.path contains "\\CloudWksInstall.exe" or tgt.process.image.path contains "\\DFInst.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Faronics Deep Freeze RMM Tool Process Activity
id: ebed0b7c-1b8d-5589-a36d-177427ca8344
status: experimental
description: |
    Detects potential processes activity of Faronics Deep Freeze RMM tool
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
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\DFServ.exe'
            - '\\DFServEx.exe'
            - '\\DFWks.exe'
            - '\\DFC.exe'
            - '\\DFStd.exe'
            - '\\DFStdInstall.exe'
            - '\\CloudWksInstall.exe'
            - '\\DFInst.exe'
    selection_image:
        Image|endswith:
            - '\\DFServ.exe'
            - '\\DFServEx.exe'
            - '\\DFWks.exe'
            - '\\DFC.exe'
            - '\\DFStd.exe'
            - '\\DFStdInstall.exe'
            - '\\CloudWksInstall.exe'
            - '\\DFInst.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Faronics Deep Freeze
level: medium
```
