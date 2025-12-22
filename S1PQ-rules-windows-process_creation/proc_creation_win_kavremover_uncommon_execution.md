```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains " run run-cmd " and (not (src.process.image.path contains "\\cleanapi.exe" or src.process.image.path contains "\\kavremover.exe"))))
```


# Original Sigma Rule:
```yaml
title: Kavremover Dropped Binary LOLBIN Usage
id: d047726b-c71c-4048-a99b-2e2f50dc107d
status: test
description: Detects the execution of a signed binary dropped by Kaspersky Lab Products Remover (kavremover) which can be abused as a LOLBIN to execute arbitrary commands and binaries.
references:
    - https://nasbench.medium.com/lolbined-using-kaspersky-endpoint-security-kes-installer-to-execute-arbitrary-commands-1c999f1b7fea
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-11-01
tags:
    - attack.defense-evasion
    - attack.t1127
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: ' run run-cmd '
    filter_main_legit_parents:
        ParentImage|endswith:
            - '\cleanapi.exe' # When launched from KES installer
            - '\kavremover.exe' # When launched from kavremover.exe
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
