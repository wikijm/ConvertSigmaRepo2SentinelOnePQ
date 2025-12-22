```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\\ManageEngine\\ServiceDesk\\" and src.process.image.path contains "\\java.exe") and (tgt.process.image.path contains "\\AppVLP.exe" or tgt.process.image.path contains "\\bash.exe" or tgt.process.image.path contains "\\bitsadmin.exe" or tgt.process.image.path contains "\\calc.exe" or tgt.process.image.path contains "\\certutil.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\curl.exe" or tgt.process.image.path contains "\\forfiles.exe" or tgt.process.image.path contains "\\mftrace.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\net.exe" or tgt.process.image.path contains "\\net1.exe" or tgt.process.image.path contains "\\notepad.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\query.exe" or tgt.process.image.path contains "\\reg.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\scrcons.exe" or tgt.process.image.path contains "\\sh.exe" or tgt.process.image.path contains "\\systeminfo.exe" or tgt.process.image.path contains "\\whoami.exe" or tgt.process.image.path contains "\\wmic.exe" or tgt.process.image.path contains "\\wscript.exe")) and (not ((tgt.process.image.path contains "\\net.exe" or tgt.process.image.path contains "\\net1.exe") and tgt.process.cmdline contains " stop"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Child Process Of Manage Engine ServiceDesk
id: cea2b7ea-792b-405f-95a1-b903ea06458f
status: test
description: Detects suspicious child processes of the "Manage Engine ServiceDesk Plus" Java web service
references:
    - https://www.horizon3.ai/manageengine-cve-2022-47966-technical-deep-dive/
    - https://github.com/horizon3ai/CVE-2022-47966/blob/3a51c6b72ebbd87392babd955a8fbeaee2090b35/CVE-2022-47966.py
    - https://blog.viettelcybersecurity.com/saml-show-stopper/
author: Florian Roth (Nextron Systems)
date: 2023-01-18
modified: 2023-08-29
tags:
    - attack.command-and-control
    - attack.t1102
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|contains|all:
            - '\ManageEngine\ServiceDesk\'
            - '\java.exe'
        Image|endswith:
            - '\AppVLP.exe'
            - '\bash.exe'
            - '\bitsadmin.exe'
            - '\calc.exe'
            - '\certutil.exe'
            - '\cscript.exe'
            - '\curl.exe'
            - '\forfiles.exe'
            - '\mftrace.exe'
            - '\mshta.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\notepad.exe'  # Often used in POCs
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\query.exe'
            - '\reg.exe'
            - '\schtasks.exe'
            - '\scrcons.exe'
            - '\sh.exe'
            - '\systeminfo.exe'
            - '\whoami.exe'  # Often used in POCs
            - '\wmic.exe'
            - '\wscript.exe'
            # - '\hh.exe'
            # - '\regsvr32.exe'
            # - '\rundll32.exe'
            # - '\scriptrunner.exe'
    filter_main_net:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: ' stop'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate sub processes started by Manage Engine ServiceDesk Pro
level: high
```
