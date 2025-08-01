```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "Offline_Winpwn" or tgt.process.cmdline contains "WinPwn " or tgt.process.cmdline contains "WinPwn.exe" or tgt.process.cmdline contains "WinPwn.ps1"))
```


# Original Sigma Rule:
```yaml
title: HackTool - WinPwn Execution
id: d557dc06-62e8-4468-a8e8-7984124908ce
related:
    - id: 851fd622-b675-4d26-b803-14bc7baa517a
      type: similar
status: test
description: |
    Detects commandline keywords indicative of potential usge of the tool WinPwn. A tool for Windows and Active Directory reconnaissance and exploitation.
author: Swachchhanda Shrawan Poudel
date: 2023-12-04
references:
    - https://github.com/S3cur3Th1sSh1t/WinPwn
    - https://www.publicnow.com/view/EB87DB49C654D9B63995FAD4C9DE3D3CC4F6C3ED?1671634841
    - https://reconshell.com/winpwn-tool-for-internal-windows-pentesting-and-ad-security/
    - https://github.com/redcanaryco/atomic-red-team/blob/4d6c4e8e23d465af7a2388620cfe3f8c76e16cf0/atomics/T1082/T1082.md
    - https://grep.app/search?q=winpwn&filter[repo][0]=redcanaryco/atomic-red-team
tags:
    - attack.credential-access
    - attack.defense-evasion
    - attack.discovery
    - attack.execution
    - attack.privilege-escalation
    - attack.t1046
    - attack.t1082
    - attack.t1106
    - attack.t1518
    - attack.t1548.002
    - attack.t1552.001
    - attack.t1555
    - attack.t1555.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'Offline_Winpwn'
            - 'WinPwn '
            - 'WinPwn.exe'
            - 'WinPwn.ps1'
    condition: selection
falsepositives:
    - Unknown
level: high
```
