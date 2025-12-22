```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\cmd.exe") and (src.process.cmdline contains "MsiExec.exe" and src.process.cmdline contains "-Embedding ")) and (not ((tgt.process.image.path contains ":\\Windows\\System32\\cmd.exe" and tgt.process.cmdline contains "C:\\Program Files\\SplunkUniversalForwarder\\bin\\") or (tgt.process.cmdline contains "\\DismFoDInstall.cmd" or (src.process.cmdline contains "\\MsiExec.exe -Embedding " and src.process.cmdline contains "Global\\MSI0000"))))))
```


# Original Sigma Rule:
```yaml
title: Suspicious MsiExec Embedding Parent
id: 4a2a2c3e-209f-4d01-b513-4155a540b469
status: test
description: Adversaries may abuse msiexec.exe to proxy the execution of malicious payloads
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md
author: frack113
date: 2022-04-16
modified: 2022-07-14
tags:
    - attack.t1218.007
    - attack.defense-evasion
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
        ParentCommandLine|contains|all:
            - 'MsiExec.exe'
            - '-Embedding '
    filter_splunk_ufw:
        Image|endswith: ':\Windows\System32\cmd.exe'
        CommandLine|contains: 'C:\Program Files\SplunkUniversalForwarder\bin\'
    filter_vs:
        - CommandLine|contains: '\DismFoDInstall.cmd'
        - ParentCommandLine|contains|all:
              - '\MsiExec.exe -Embedding '
              - 'Global\MSI0000'
    condition: selection and not 1 of filter*
falsepositives:
    - Unknown
level: medium
```
