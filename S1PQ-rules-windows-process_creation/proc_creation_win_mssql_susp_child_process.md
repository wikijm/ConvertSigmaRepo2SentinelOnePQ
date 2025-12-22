```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\sqlservr.exe" and (tgt.process.image.path contains "\\bash.exe" or tgt.process.image.path contains "\\bitsadmin.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\netstat.exe" or tgt.process.image.path contains "\\nltest.exe" or tgt.process.image.path contains "\\ping.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\sh.exe" or tgt.process.image.path contains "\\systeminfo.exe" or tgt.process.image.path contains "\\tasklist.exe" or tgt.process.image.path contains "\\wsl.exe")) and (not (src.process.image.path contains "C:\\Program Files\\Microsoft SQL Server\\" and src.process.image.path contains "DATEV_DBENGINE\\MSSQL\\Binn\\sqlservr.exe" and tgt.process.image.path="C:\\Windows\\System32\\cmd.exe" and tgt.process.cmdline contains "\"C:\\Windows\\system32\\cmd.exe\" "))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Child Process Of SQL Server
id: 869b9ca7-9ea2-4a5a-8325-e80e62f75445
related:
    - id: 344482e4-a477-436c-aa70-7536d18a48c7
      type: obsolete
status: test
description: Detects suspicious child processes of the SQLServer process. This could indicate potential RCE or SQL Injection.
references:
    - Internal Research
author: FPT.EagleEye Team, wagga
date: 2020-12-11
modified: 2023-05-04
tags:
    - attack.t1505.003
    - attack.t1190
    - attack.initial-access
    - attack.persistence
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\sqlservr.exe'
        Image|endswith:
            # You can add other uncommon or suspicious processes
            - '\bash.exe'
            - '\bitsadmin.exe'
            - '\cmd.exe'
            - '\netstat.exe'
            - '\nltest.exe'
            - '\ping.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\sh.exe'
            - '\systeminfo.exe'
            - '\tasklist.exe'
            - '\wsl.exe'
    filter_optional_datev:
        ParentImage|startswith: 'C:\Program Files\Microsoft SQL Server\'
        ParentImage|endswith: 'DATEV_DBENGINE\MSSQL\Binn\sqlservr.exe'
        Image: 'C:\Windows\System32\cmd.exe'
        CommandLine|startswith: '"C:\Windows\system32\cmd.exe" '
    condition: selection and not 1 of filter_optional_*
level: high
```
