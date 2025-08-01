```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\wusa.exe" and tgt.process.cmdline contains "/extract:") and (tgt.process.cmdline contains ":\PerfLogs\" or tgt.process.cmdline contains ":\Users\Public\" or tgt.process.cmdline contains ":\Windows\Temp\" or tgt.process.cmdline contains "\Appdata\Local\Temp\")))
```


# Original Sigma Rule:
```yaml
title: Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths
id: c74c0390-3e20-41fd-a69a-128f0275a5ea
related:
    - id: 59b39960-5f9d-4a49-9cef-1e4d2c1d0cb9
      type: derived
status: test
description: |
    Detects the execution of the "wusa.exe" (Windows Update Standalone Installer) utility to extract ".cab" files using the "/extract" argument from potentially suspicious paths.
references:
    - https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html
    - https://www.echotrail.io/insights/search/wusa.exe/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-05
modified: 2023-11-28
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_root:
        Image|endswith: '\wusa.exe'
        CommandLine|contains: '/extract:'
    selection_paths:
        CommandLine|contains:
            - ':\PerfLogs\'
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - '\Appdata\Local\Temp\'
            # - '\Desktop\'
            # - '\Downloads\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
