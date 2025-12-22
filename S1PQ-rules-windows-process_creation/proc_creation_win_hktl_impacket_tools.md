```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\goldenPac" or tgt.process.image.path contains "\\karmaSMB" or tgt.process.image.path contains "\\kintercept" or tgt.process.image.path contains "\\ntlmrelayx" or tgt.process.image.path contains "\\rpcdump" or tgt.process.image.path contains "\\samrdump" or tgt.process.image.path contains "\\secretsdump" or tgt.process.image.path contains "\\smbexec" or tgt.process.image.path contains "\\smbrelayx" or tgt.process.image.path contains "\\wmiexec" or tgt.process.image.path contains "\\wmipersist") or (tgt.process.image.path contains "\\atexec_windows.exe" or tgt.process.image.path contains "\\dcomexec_windows.exe" or tgt.process.image.path contains "\\dpapi_windows.exe" or tgt.process.image.path contains "\\findDelegation_windows.exe" or tgt.process.image.path contains "\\GetADUsers_windows.exe" or tgt.process.image.path contains "\\GetNPUsers_windows.exe" or tgt.process.image.path contains "\\getPac_windows.exe" or tgt.process.image.path contains "\\getST_windows.exe" or tgt.process.image.path contains "\\getTGT_windows.exe" or tgt.process.image.path contains "\\GetUserSPNs_windows.exe" or tgt.process.image.path contains "\\ifmap_windows.exe" or tgt.process.image.path contains "\\mimikatz_windows.exe" or tgt.process.image.path contains "\\netview_windows.exe" or tgt.process.image.path contains "\\nmapAnswerMachine_windows.exe" or tgt.process.image.path contains "\\opdump_windows.exe" or tgt.process.image.path contains "\\psexec_windows.exe" or tgt.process.image.path contains "\\rdp_check_windows.exe" or tgt.process.image.path contains "\\sambaPipe_windows.exe" or tgt.process.image.path contains "\\smbclient_windows.exe" or tgt.process.image.path contains "\\smbserver_windows.exe" or tgt.process.image.path contains "\\sniff_windows.exe" or tgt.process.image.path contains "\\sniffer_windows.exe" or tgt.process.image.path contains "\\split_windows.exe" or tgt.process.image.path contains "\\ticketer_windows.exe")))
```


# Original Sigma Rule:
```yaml
title: HackTool - Impacket Tools Execution
id: 4627c6ae-6899-46e2-aa0c-6ebcb1becd19
status: test
description: Detects the execution of different compiled Windows binaries of the impacket toolset (based on names or part of their names - could lead to false positives)
references:
    - https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries
author: Florian Roth (Nextron Systems)
date: 2021-07-24
modified: 2023-02-07
tags:
    - attack.collection
    - attack.execution
    - attack.credential-access
    - attack.t1557.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|contains:
              - '\goldenPac'
              - '\karmaSMB'
              - '\kintercept'
              - '\ntlmrelayx'
              - '\rpcdump'
              - '\samrdump'
              - '\secretsdump'
              - '\smbexec'
              - '\smbrelayx'
              - '\wmiexec'
              - '\wmipersist'
        - Image|endswith:
              - '\atexec_windows.exe'
              - '\dcomexec_windows.exe'
              - '\dpapi_windows.exe'
              - '\findDelegation_windows.exe'
              - '\GetADUsers_windows.exe'
              - '\GetNPUsers_windows.exe'
              - '\getPac_windows.exe'
              - '\getST_windows.exe'
              - '\getTGT_windows.exe'
              - '\GetUserSPNs_windows.exe'
              - '\ifmap_windows.exe'
              - '\mimikatz_windows.exe'
              - '\netview_windows.exe'
              - '\nmapAnswerMachine_windows.exe'
              - '\opdump_windows.exe'
              - '\psexec_windows.exe'
              - '\rdp_check_windows.exe'
              - '\sambaPipe_windows.exe'
              - '\smbclient_windows.exe'
              - '\smbserver_windows.exe'
              - '\sniff_windows.exe'
              - '\sniffer_windows.exe'
              - '\split_windows.exe'
              - '\ticketer_windows.exe'
              # - '\addcomputer_windows.exe'
              # - '\esentutl_windows.exe'
              # - '\getArch_windows.exe'
              # - '\lookupsid_windows.exe'
              # - '\mqtt_check_windows.exe'
              # - '\mssqlclient_windows.exe'
              # - '\mssqlinstance_windows.exe'
              # - '\ntfs-read_windows.exe'
              # - '\ping_windows.exe'
              # - '\ping6_windows.exe'
              # - '\raiseChild_windows.exe'
              # - '\reg_windows.exe'
              # - '\registry-read_windows.exe'
              # - '\services_windows.exe'
              # - '\wmiquery_windows.exe'
    condition: selection
falsepositives:
    - Legitimate use of the impacket tools
level: high
```
