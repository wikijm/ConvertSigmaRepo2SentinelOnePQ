```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "PetitPotam" or tgt.process.image.path contains "RottenPotato" or tgt.process.image.path contains "HotPotato" or tgt.process.image.path contains "JuicyPotato" or tgt.process.image.path contains "\just_dce_" or tgt.process.image.path contains "Juicy Potato" or tgt.process.image.path contains "\temp\rot.exe" or tgt.process.image.path contains "\Potato.exe" or tgt.process.image.path contains "\SpoolSample.exe" or tgt.process.image.path contains "\Responder.exe" or tgt.process.image.path contains "\smbrelayx" or tgt.process.image.path contains "\ntlmrelayx" or tgt.process.image.path contains "\LocalPotato") or (tgt.process.cmdline contains "Invoke-Tater" or tgt.process.cmdline contains " smbrelay" or tgt.process.cmdline contains " ntlmrelay" or tgt.process.cmdline contains "cme smb " or tgt.process.cmdline contains " /ntlm:NTLMhash " or tgt.process.cmdline contains "Invoke-PetitPotam" or tgt.process.cmdline="*.exe -t * -p *") or (tgt.process.cmdline contains ".exe -c \"{" and tgt.process.cmdline contains "}\" -z")) and (not (tgt.process.image.path contains "HotPotatoes6" or tgt.process.image.path contains "HotPotatoes7" or tgt.process.image.path contains "HotPotatoes "))))
```


# Original Sigma Rule:
```yaml
title: Potential SMB Relay Attack Tool Execution
id: 5589ab4f-a767-433c-961d-c91f3f704db1
status: test
description: Detects different hacktools used for relay attacks on Windows for privilege escalation
references:
    - https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
    - https://pentestlab.blog/2017/04/13/hot-potato/
    - https://github.com/ohpe/juicy-potato
    - https://hunter2.gitbook.io/darthsidious/other/war-stories/domain-admin-in-30-minutes
    - https://hunter2.gitbook.io/darthsidious/execution/responder-with-ntlm-relay-and-empire
    - https://www.localpotato.com/
author: Florian Roth (Nextron Systems)
date: 2021-07-24
modified: 2023-02-14
tags:
    - attack.execution
    - attack.credential-access
    - attack.t1557.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_pe:
        Image|contains:
            - 'PetitPotam'
            - 'RottenPotato'
            - 'HotPotato'
            - 'JuicyPotato'
            - '\just_dce_'
            - 'Juicy Potato'
            - '\temp\rot.exe'
            - '\Potato.exe'
            - '\SpoolSample.exe'
            - '\Responder.exe'
            - '\smbrelayx'
            - '\ntlmrelayx'
            - '\LocalPotato'
    selection_script:
        CommandLine|contains:
            - 'Invoke-Tater'
            - ' smbrelay'
            - ' ntlmrelay'
            - 'cme smb '
            - ' /ntlm:NTLMhash '
            - 'Invoke-PetitPotam'
            - '.exe -t * -p '  # JuicyPotatoNG pattern https://github.com/antonioCoco/JuicyPotatoNG
    selection_juicypotato_enum:  # appears when JuicyPotatoNG is used with -b
        CommandLine|contains: '.exe -c "{'
        CommandLine|endswith: '}" -z'
    filter_hotpotatoes:  # known goodware https://hotpot.uvic.ca/
        Image|contains:
            - 'HotPotatoes6'
            - 'HotPotatoes7'
            - 'HotPotatoes ' # Covers the following: 'HotPotatoes 6', 'HotPotatoes 7', 'HotPotatoes Help', 'HotPotatoes Tutorial'
    condition: 1 of selection_* and not 1 of filter_*
falsepositives:
    - Legitimate files with these rare hacktool names
level: critical
```
