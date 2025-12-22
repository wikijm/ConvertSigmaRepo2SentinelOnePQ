```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\hashcat.exe" or (tgt.process.cmdline contains "-a " and tgt.process.cmdline contains "-m 1000 " and tgt.process.cmdline contains "-r ")))
```


# Original Sigma Rule:
```yaml
title: HackTool - Hashcat Password Cracker Execution
id: 39b31e81-5f5f-4898-9c0e-2160cfc0f9bf
status: test
description: Execute Hashcat.exe with provided SAM file from registry of Windows and Password list to crack against
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1110.002/T1110.002.md#atomic-test-1---password-cracking-with-hashcat
    - https://hashcat.net/wiki/doku.php?id=hashcat
author: frack113
date: 2021-12-27
modified: 2023-02-04
tags:
    - attack.credential-access
    - attack.t1110.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\hashcat.exe'
    selection_cli:
        CommandLine|contains|all:
            - '-a '
            - '-m 1000 '
            - '-r '
    condition: 1 of selection_*
falsepositives:
    - Tools that use similar command line flags and values
level: high
```
