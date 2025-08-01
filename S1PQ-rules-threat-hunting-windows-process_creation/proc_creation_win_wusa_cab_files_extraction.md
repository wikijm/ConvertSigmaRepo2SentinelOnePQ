```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\wusa.exe" and tgt.process.cmdline contains "/extract:"))
```


# Original Sigma Rule:
```yaml
title: Cab File Extraction Via Wusa.EXE
id: 59b39960-5f9d-4a49-9cef-1e4d2c1d0cb9
related:
    - id: c74c0390-3e20-41fd-a69a-128f0275a5ea
      type: derived
status: test
description: |
    Detects execution of the "wusa.exe" (Windows Update Standalone Installer) utility to extract cab using the "/extract" argument that is no longer supported.
references:
    - https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-04
modified: 2024-08-15
tags:
    - attack.execution
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wusa.exe'
        CommandLine|contains: '/extract:'
    condition: selection
falsepositives:
    - The "extract" flag still works on older 'wusa.exe' versions, which could be a legitimate use (monitor the path of the cab being extracted)
level: medium
```
