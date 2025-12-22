```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\crackmapexec.exe" or tgt.process.cmdline contains " -M pe_inject " or (tgt.process.cmdline contains " --local-auth" and tgt.process.cmdline contains " -u " and tgt.process.cmdline contains " -x ") or (tgt.process.cmdline contains " --local-auth" and tgt.process.cmdline contains " -u " and tgt.process.cmdline contains " -p " and tgt.process.cmdline contains " -H 'NTHASH'") or (tgt.process.cmdline contains " mssql " and tgt.process.cmdline contains " -u " and tgt.process.cmdline contains " -p " and tgt.process.cmdline contains " -M " and tgt.process.cmdline contains " -d ") or (tgt.process.cmdline contains " smb " and tgt.process.cmdline contains " -u " and tgt.process.cmdline contains " -H " and tgt.process.cmdline contains " -M " and tgt.process.cmdline contains " -o ") or (tgt.process.cmdline contains " smb " and tgt.process.cmdline contains " -u " and tgt.process.cmdline contains " -p " and tgt.process.cmdline contains " --local-auth")) or ((tgt.process.cmdline contains " --local-auth" and tgt.process.cmdline contains " -u " and tgt.process.cmdline contains " -p ") and (tgt.process.cmdline contains " 10." and tgt.process.cmdline contains " 192.168." and tgt.process.cmdline contains "/24 "))))
```


# Original Sigma Rule:
```yaml
title: HackTool - CrackMapExec Execution
id: 42a993dd-bb3e-48c8-b372-4d6684c4106c
status: test
description: This rule detect common flag combinations used by CrackMapExec in order to detect its use even if the binary has been replaced.
references:
    - https://mpgn.gitbook.io/crackmapexec/smb-protocol/authentication/checking-credentials-local
    - https://www.mandiant.com/resources/telegram-malware-iranian-espionage
    - https://www.infosecmatter.com/crackmapexec-module-library/?cmem=mssql-mimikatz
    - https://www.infosecmatter.com/crackmapexec-module-library/?cmem=smb-pe_inject
author: Florian Roth (Nextron Systems)
date: 2022-02-25
modified: 2023-03-08
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege-escalation
    - attack.credential-access
    - attack.discovery
    - attack.t1047
    - attack.t1053
    - attack.t1059.003
    - attack.t1059.001
    - attack.t1110
    - attack.t1201
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        Image|endswith: '\crackmapexec.exe'
    selection_special:
        CommandLine|contains: ' -M pe_inject '
    selection_execute:
        CommandLine|contains|all:
            - ' --local-auth'
            - ' -u '
            - ' -x '
    selection_hash:
        CommandLine|contains|all:
            - ' --local-auth'
            - ' -u '
            - ' -p '
            - " -H 'NTHASH'"
    selection_module_mssql:
        CommandLine|contains|all:
            - ' mssql '
            - ' -u '
            - ' -p '
            - ' -M '
            - ' -d '
    selection_module_smb1:
        CommandLine|contains|all:
            - ' smb '
            - ' -u '
            - ' -H '
            - ' -M '
            - ' -o '
    selection_module_smb2:
        CommandLine|contains|all:
            - ' smb '
            - ' -u '
            - ' -p '
            - ' --local-auth'
    part_localauth_1:
        CommandLine|contains|all:
            - ' --local-auth'
            - ' -u '
            - ' -p '
    part_localauth_2:
        CommandLine|contains|all:
            - ' 10.'
            - ' 192.168.'
            - '/24 '
    condition: 1 of selection_* or all of part_localauth*
falsepositives:
    - Unknown
level: high
```
