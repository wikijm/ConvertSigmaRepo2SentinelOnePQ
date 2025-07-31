```sql
// Translated content (automatically translated on 31-07-2025 02:23:44):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\SyncAppvPublishingServer.vbs" and tgt.process.cmdline contains ";")) | columns ComputerName,tgt.process.user,tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code
id: 36475a7d-0f6d-4dce-9b01-6aeb473bbaf1
status: test
description: Executes arbitrary PowerShell code using SyncAppvPublishingServer.vbs
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1216/T1216.md
    - https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/
author: frack113
date: 2021-07-16
modified: 2022-06-22
tags:
    - attack.defense-evasion
    - attack.t1218
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\SyncAppvPublishingServer.vbs'
            - ';'  # at a minimum, a semi-colon is required
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium
```
