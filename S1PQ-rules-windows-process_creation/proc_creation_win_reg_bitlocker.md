```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "REG" and tgt.process.cmdline contains "ADD" and tgt.process.cmdline contains "\\SOFTWARE\\Policies\\Microsoft\\FVE" and tgt.process.cmdline contains "/v" and tgt.process.cmdline contains "/f") and (tgt.process.cmdline contains "EnableBDEWithNoTPM" or tgt.process.cmdline contains "UseAdvancedStartup" or tgt.process.cmdline contains "UseTPM" or tgt.process.cmdline contains "UseTPMKey" or tgt.process.cmdline contains "UseTPMKeyPIN" or tgt.process.cmdline contains "RecoveryKeyMessageSource" or tgt.process.cmdline contains "UseTPMPIN" or tgt.process.cmdline contains "RecoveryKeyMessage")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Reg Add BitLocker
id: 0e0255bf-2548-47b8-9582-c0955c9283f5
status: test
description: Detects suspicious addition to BitLocker related registry keys via the reg.exe utility
references:
    - https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/
author: frack113
date: 2021-11-15
modified: 2022-09-09
tags:
    - attack.impact
    - attack.t1486
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'REG'
            - 'ADD'
            - '\SOFTWARE\Policies\Microsoft\FVE'
            - '/v'
            - '/f'
        CommandLine|contains:
            - 'EnableBDEWithNoTPM'
            - 'UseAdvancedStartup'
            - 'UseTPM'
            - 'UseTPMKey'
            - 'UseTPMKeyPIN'
            - 'RecoveryKeyMessageSource'
            - 'UseTPMPIN'
            - 'RecoveryKeyMessage'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
