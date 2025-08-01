```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\dllhost.exe" and (tgt.process.cmdline in ("dllhost.exe","dllhost"))) and (not not (tgt.process.cmdline matches "\.*"))))
```


# Original Sigma Rule:
```yaml
title: Dllhost.EXE Execution Anomaly
id: e7888eb1-13b0-4616-bd99-4bc0c2b054b9
status: test
description: Detects a "dllhost" process spawning with no commandline arguments which is very rare to happen and could indicate process injection activity or malware mimicking similar system processes.
references:
    - https://redcanary.com/blog/child-processes/
    - https://nasbench.medium.com/what-is-the-dllhost-exe-process-actually-running-ef9fe4c19c08
    - https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/goofy-guineapig/NCSC-MAR-Goofy-Guineapig.pdf
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-27
modified: 2023-05-15
tags:
    - attack.defense-evasion
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dllhost.exe'
        CommandLine:
            - 'dllhost.exe'
            - 'dllhost'
    filter_main_null:
        CommandLine: null
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
```
