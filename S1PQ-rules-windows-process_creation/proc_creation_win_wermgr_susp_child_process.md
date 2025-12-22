```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\wermgr.exe" and (tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\ipconfig.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\net.exe" or tgt.process.image.path contains "\\net1.exe" or tgt.process.image.path contains "\\netstat.exe" or tgt.process.image.path contains "\\nslookup.exe" or tgt.process.image.path contains "\\powershell_ise.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\systeminfo.exe" or tgt.process.image.path contains "\\whoami.exe" or tgt.process.image.path contains "\\wscript.exe")) and (not (tgt.process.image.path contains "\\rundll32.exe" and (tgt.process.cmdline contains "C:\\Windows\\system32\\WerConCpl.dll" and tgt.process.cmdline contains "LaunchErcApp ") and (tgt.process.cmdline contains "-queuereporting" or tgt.process.cmdline contains "-responsepester")))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Child Process Of Wermgr.EXE
id: 396f6630-f3ac-44e3-bfc8-1b161bc00c4e
related:
    - id: 5394fcc7-aeb2-43b5-9a09-cac9fc5edcd5
      type: similar
status: test
description: Detects suspicious Windows Error Reporting manager (wermgr.exe) child process
references:
    - https://www.trendmicro.com/en_us/research/22/j/black-basta-infiltrates-networks-via-qakbot-brute-ratel-and-coba.html
    - https://www.echotrail.io/insights/search/wermgr.exe
    - https://github.com/binderlabs/DirCreate2System
author: Florian Roth (Nextron Systems)
date: 2022-10-14
modified: 2024-08-29
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1055
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\wermgr.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\cscript.exe'
            - '\ipconfig.exe'
            - '\mshta.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\netstat.exe'
            - '\nslookup.exe'
            - '\powershell_ise.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\systeminfo.exe'
            - '\whoami.exe'
            - '\wscript.exe'
    filter_main_rundll32:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains|all:
            - 'C:\Windows\system32\WerConCpl.dll'
            - 'LaunchErcApp '
        CommandLine|contains:
            - '-queuereporting'
            - '-responsepester'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
