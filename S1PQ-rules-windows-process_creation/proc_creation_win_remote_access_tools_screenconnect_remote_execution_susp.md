```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.cmdline contains ":\Windows\TEMP\ScreenConnect\" and src.process.cmdline contains "run.cmd") and (tgt.process.image.path contains "\bitsadmin.exe" or tgt.process.image.path contains "\cmd.exe" or tgt.process.image.path contains "\curl.exe" or tgt.process.image.path contains "\dllhost.exe" or tgt.process.image.path contains "\net.exe" or tgt.process.image.path contains "\nltest.exe" or tgt.process.image.path contains "\powershell.exe" or tgt.process.image.path contains "\pwsh.exe" or tgt.process.image.path contains "\rundll32.exe" or tgt.process.image.path contains "\wevtutil.exe")))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - ScreenConnect Potential Suspicious Remote Command Execution
id: 7b582f1a-b318-4c6a-bf4e-66fe49bf55a5
related:
    - id: d1a401ab-8c47-4e86-a7d8-2460b6a53e4a
      type: derived
status: test
description: |
    Detects potentially suspicious child processes launched via the ScreenConnect client service.
references:
    - https://www.mandiant.com/resources/telegram-malware-iranian-espionage
    - https://docs.connectwise.com/ConnectWise_Control_Documentation/Get_started/Host_client/View_menu/Backstage_mode
    - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
    - https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems), @Kostastsale
date: 2022-02-25
modified: 2024-02-28
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentCommandLine|contains|all:
            - ':\Windows\TEMP\ScreenConnect\'
            - 'run.cmd'
        Image|endswith:
            - '\bitsadmin.exe'
            - '\cmd.exe'
            - '\curl.exe'
            - '\dllhost.exe'
            - '\net.exe'
            - '\nltest.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\rundll32.exe'
            - '\wevtutil.exe'
    condition: selection
falsepositives:
    - If the script being executed make use of any of the utilities mentioned in the detection then they should filtered out or allowed.
level: medium
```
