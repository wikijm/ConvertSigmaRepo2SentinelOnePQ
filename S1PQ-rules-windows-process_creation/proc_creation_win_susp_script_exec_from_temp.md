```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\cscript.exe") and (tgt.process.cmdline contains "\\Windows\\Temp" or tgt.process.cmdline contains "\\Temporary Internet" or tgt.process.cmdline contains "\\AppData\\Local\\Temp" or tgt.process.cmdline contains "\\AppData\\Roaming\\Temp" or tgt.process.cmdline contains "%TEMP%" or tgt.process.cmdline contains "%TMP%" or tgt.process.cmdline contains "%LocalAppData%\\Temp")) and (not (tgt.process.cmdline contains " >" or tgt.process.cmdline contains "Out-File" or tgt.process.cmdline contains "ConvertTo-Json" or tgt.process.cmdline contains "-WindowStyle hidden -Verb runAs" or tgt.process.cmdline contains "\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\Temp\\Amazon\\EC2-Windows\\"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Script Execution From Temp Folder
id: a6a39bdb-935c-4f0a-ab77-35f4bbf44d33
status: test
description: Detects a suspicious script executions from temporary folder
references:
    - https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/
author: Florian Roth (Nextron Systems), Max Altgelt (Nextron Systems), Tim Shelton
date: 2021-07-14
modified: 2022-10-05
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\mshta.exe'
            - '\wscript.exe'
            - '\cscript.exe'
        CommandLine|contains:
            - '\Windows\Temp'
            - '\Temporary Internet'
            - '\AppData\Local\Temp'
            - '\AppData\Roaming\Temp'
            - '%TEMP%'
            - '%TMP%'
            - '%LocalAppData%\Temp'
    filter:
        CommandLine|contains:
            - ' >'
            - 'Out-File'
            - 'ConvertTo-Json'
            - '-WindowStyle hidden -Verb runAs'  # VSCode behaviour if file cannot be written as current user
            - '\Windows\system32\config\systemprofile\AppData\Local\Temp\Amazon\EC2-Windows\' # EC2 AWS
    condition: selection and not filter
falsepositives:
    - Administrative scripts
level: high
```
