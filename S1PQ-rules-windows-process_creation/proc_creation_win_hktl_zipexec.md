```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "/generic:Microsoft_Windows_Shell_ZipFolder:filename=" and tgt.process.cmdline contains ".zip" and tgt.process.cmdline contains "/pass:" and tgt.process.cmdline contains "/user:") or (tgt.process.cmdline contains "/delete" and tgt.process.cmdline contains "Microsoft_Windows_Shell_ZipFolder:filename=" and tgt.process.cmdline contains ".zip")))
```


# Original Sigma Rule:
```yaml
title: Suspicious ZipExec Execution
id: 90dcf730-1b71-4ae7-9ffc-6fcf62bd0132
status: test
description: ZipExec is a Proof-of-Concept (POC) tool to wrap binary-based tools into a password-protected zip file.
references:
    - https://twitter.com/SBousseaden/status/1451237393017839616
    - https://github.com/Tylous/ZipExec
author: frack113
date: 2021-11-07
modified: 2022-12-25
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1218
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    run:
        CommandLine|contains|all:
            - '/generic:Microsoft_Windows_Shell_ZipFolder:filename='
            - '.zip'
            - '/pass:'
            - '/user:'
    delete:
        CommandLine|contains|all:
            - '/delete'
            - 'Microsoft_Windows_Shell_ZipFolder:filename='
            - '.zip'
    condition: run or delete
falsepositives:
    - Unknown
level: medium
```
