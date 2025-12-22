```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "VBoxRT.dll,RTR3Init" or tgt.process.cmdline contains "VBoxC.dll" or tgt.process.cmdline contains "VBoxDrv.sys") or (tgt.process.cmdline contains "startvm" or tgt.process.cmdline contains "controlvm")))
```


# Original Sigma Rule:
```yaml
title: Virtualbox Driver Installation or Starting of VMs
id: bab049ca-7471-4828-9024-38279a4c04da
status: test
description: Adversaries can carry out malicious operations using a virtual instance to avoid detection. This rule is built to detect the registration of the Virtualbox driver or start of a Virtualbox VM.
references:
    - https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/
    - https://threatpost.com/maze-ransomware-ragnar-locker-virtual-machine/159350/
author: Janantha Marasinghe
date: 2020-09-26
modified: 2025-07-29
tags:
    - attack.defense-evasion
    - attack.t1564.006
    - attack.t1564
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains:
            - 'VBoxRT.dll,RTR3Init'
            - 'VBoxC.dll'
            - 'VBoxDrv.sys'
    selection_2:
        CommandLine|contains:
            - 'startvm'
            - 'controlvm'
    condition: 1 of selection_*
falsepositives:
    - This may have false positives on hosts where Virtualbox is legitimately being used for operations
level: low
```
