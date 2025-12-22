```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "Import-Certificate" and tgt.process.cmdline contains " -FilePath " and tgt.process.cmdline contains "Cert:\\LocalMachine\\Root") and (tgt.process.cmdline contains "\\AppData\\Local\\Temp\\" or tgt.process.cmdline contains ":\\Windows\\TEMP\\" or tgt.process.cmdline contains "\\Desktop\\" or tgt.process.cmdline contains "\\Downloads\\" or tgt.process.cmdline contains "\\Perflogs\\" or tgt.process.cmdline contains ":\\Users\\Public\\")))
```


# Original Sigma Rule:
```yaml
title: Root Certificate Installed From Susp Locations
id: 5f6a601c-2ecb-498b-9c33-660362323afa
status: test
description: Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
references:
    - https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
    - https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate?view=windowsserver2022-ps
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-09
modified: 2023-01-16
tags:
    - attack.defense-evasion
    - attack.t1553.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'Import-Certificate'
            - ' -FilePath '
            - 'Cert:\LocalMachine\Root'
        CommandLine|contains:
            - '\AppData\Local\Temp\'
            - ':\Windows\TEMP\'
            - '\Desktop\'
            - '\Downloads\'
            - '\Perflogs\'
            - ':\Users\Public\'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
