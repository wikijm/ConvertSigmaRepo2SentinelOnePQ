```sql
// Translated content (automatically translated on 24-08-2025 02:10:54):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains " -t msi-install " and tgt.process.cmdline contains " -i http"))
```


# Original Sigma Rule:
```yaml
title: Arbitrary MSI Download Via Devinit.EXE
id: 90d50722-0483-4065-8e35-57efaadd354d
status: test
description: Detects a certain command line flag combination used by "devinit.exe", which can be abused as a LOLBIN to download arbitrary MSI packages on a Windows system
references:
    - https://twitter.com/mrd0x/status/1460815932402679809
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Devinit/
author: Florian Roth (Nextron Systems)
date: 2022-01-11
modified: 2023-04-06
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' -t msi-install '
            - ' -i http'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
