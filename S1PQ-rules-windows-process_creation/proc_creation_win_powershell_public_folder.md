```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe") and (tgt.process.cmdline contains "-f C:\\Users\\Public" or tgt.process.cmdline contains "-f \"C:\\Users\\Public" or tgt.process.cmdline contains "-f %Public%" or tgt.process.cmdline contains "-fi C:\\Users\\Public" or tgt.process.cmdline contains "-fi \"C:\\Users\\Public" or tgt.process.cmdline contains "-fi %Public%" or tgt.process.cmdline contains "-fil C:\\Users\\Public" or tgt.process.cmdline contains "-fil \"C:\\Users\\Public" or tgt.process.cmdline contains "-fil %Public%" or tgt.process.cmdline contains "-file C:\\Users\\Public" or tgt.process.cmdline contains "-file \"C:\\Users\\Public" or tgt.process.cmdline contains "-file %Public%")))
```


# Original Sigma Rule:
```yaml
title: Execution of Powershell Script in Public Folder
id: fb9d3ff7-7348-46ab-af8c-b55f5fbf39b4
status: test
description: This rule detects execution of PowerShell scripts located in the "C:\Users\Public" folder
references:
    - https://www.mandiant.com/resources/evolution-of-fin7
author: Max Altgelt (Nextron Systems)
date: 2022-04-06
modified: 2022-07-14
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - '-f C:\Users\Public'
            - '-f "C:\Users\Public'
            - '-f %Public%'
            - '-fi C:\Users\Public'
            - '-fi "C:\Users\Public'
            - '-fi %Public%'
            - '-fil C:\Users\Public'
            - '-fil "C:\Users\Public'
            - '-fil %Public%'
            - '-file C:\Users\Public'
            - '-file "C:\Users\Public'
            - '-file %Public%'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
