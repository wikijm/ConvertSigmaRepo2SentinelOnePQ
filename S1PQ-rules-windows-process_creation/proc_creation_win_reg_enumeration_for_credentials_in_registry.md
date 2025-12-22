```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\reg.exe" and (tgt.process.cmdline contains " query " and tgt.process.cmdline contains "/t " and tgt.process.cmdline contains "REG_SZ" and tgt.process.cmdline contains "/s")) and ((tgt.process.cmdline contains "/f " and tgt.process.cmdline contains "HKLM") or (tgt.process.cmdline contains "/f " and tgt.process.cmdline contains "HKCU") or tgt.process.cmdline contains "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions")))
```


# Original Sigma Rule:
```yaml
title: Enumeration for Credentials in Registry
id: e0b0c2ab-3d52-46d9-8cb7-049dc775fbd1
status: test
description: |
    Adversaries may search the Registry on compromised systems for insecurely stored credentials.
    The Windows Registry stores configuration information that can be used by the system or other programs.
    Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.002/T1552.002.md
author: frack113
date: 2021-12-20
modified: 2022-12-25
tags:
    - attack.credential-access
    - attack.t1552.002
logsource:
    category: process_creation
    product: windows
detection:
    reg:
        Image|endswith: '\reg.exe'
        CommandLine|contains|all:
            - ' query '
            - '/t '
            - 'REG_SZ'
            - '/s'
    hive:
        - CommandLine|contains|all:
              - '/f '
              - 'HKLM'
        - CommandLine|contains|all:
              - '/f '
              - 'HKCU'
        - CommandLine|contains: 'HKCU\Software\SimonTatham\PuTTY\Sessions'
    condition: reg and hive
falsepositives:
    - Unknown
level: medium
```
