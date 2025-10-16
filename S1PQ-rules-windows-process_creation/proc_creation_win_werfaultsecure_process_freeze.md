```sql
// Translated content (automatically translated on 16-10-2025 01:56:13):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path="C:\\Windows\\System32\\WerFaultSecure.exe" and (tgt.process.cmdline contains " /h " and tgt.process.cmdline contains " /pid " and tgt.process.cmdline contains " /tid " and tgt.process.cmdline contains " /encfile " and tgt.process.cmdline contains " /cancel " and tgt.process.cmdline contains " /type " and tgt.process.cmdline contains " 268310")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Process Suspension via WERFaultSecure through EDR-Freeze
id: 1f0b4cac-9c81-41f4-95d0-8475ff46b3e2
status: experimental
description: |
    Detects attempts to freeze a process likely an EDR or an antimalware service process through EDR-Freeze that abuses the WerFaultSecure.exe process to suspend security software.
references:
    - https://www.zerosalarium.com/2025/09/EDR-Freeze-Puts-EDRs-Antivirus-Into-Coma.html
    - https://github.com/TwoSevenOneT/EDR-Freeze/blob/a7f61030b36fbde89871f393488f7075d2aa89f6/EDR-Freeze.cpp#L53
author: Jason (https://github.com/0xbcf)
date: 2025-09-23
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'C:\Windows\System32\WerFaultSecure.exe'
        CommandLine|contains|all:
            - ' /h '
            - ' /pid ' # Antimalware or EDR process pid will be after this line
            - ' /tid '
            - ' /encfile '
            - ' /cancel '
            - ' /type '
            - ' 268310'
    condition: selection
falsepositives:
    - Legitimate usage of WerFaultSecure for debugging purposes
level: high
```
