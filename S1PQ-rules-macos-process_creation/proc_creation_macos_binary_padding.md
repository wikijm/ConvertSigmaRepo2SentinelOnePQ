```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/truncate" and tgt.process.cmdline contains "-s +") or (tgt.process.image.path contains "/dd" and (tgt.process.cmdline contains "if=/dev/zero" or tgt.process.cmdline contains "if=/dev/random" or tgt.process.cmdline contains "if=/dev/urandom"))))
```


# Original Sigma Rule:
```yaml
title: Binary Padding - MacOS
id: 95361ce5-c891-4b0a-87ca-e24607884a96
status: test
description: Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This rule detect using dd and truncate to add a junk data to file.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027.001/T1027.001.md
    - https://linux.die.net/man/1/truncate
    - https://linux.die.net/man/1/dd
author: 'Igor Fits, Mikhail Larin, oscd.community'
date: 2020-10-19
modified: 2023-02-17
tags:
    - attack.defense-evasion
    - attack.t1027.001
logsource:
    product: macos
    category: process_creation
detection:
    selection_truncate:
        Image|endswith: '/truncate'
        CommandLine|contains: '-s +'
    selection_dd:
        Image|endswith: '/dd'
        CommandLine|contains:
            - 'if=/dev/zero' # if input is not /dev/zero, then there is no null padding
            - 'if=/dev/random' # high-quality random data
            - 'if=/dev/urandom' # low-quality random data
    condition: 1 of selection_*
falsepositives:
    - Legitimate script work
level: high
```
