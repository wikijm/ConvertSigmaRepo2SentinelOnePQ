```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/sysctl" or tgt.process.cmdline contains "sysctl") and (tgt.process.cmdline contains "hw." or tgt.process.cmdline contains "kern." or tgt.process.cmdline contains "machdep.")))
```


# Original Sigma Rule:
```yaml
title: System Information Discovery Via Sysctl - MacOS
id: 6ff08e55-ea53-4f27-94a1-eff92e6d9d5c
status: test
description: |
    Detects the execution of "sysctl" with specific arguments that have been used by threat actors and malware. It provides system hardware information.
    This process is primarily used to detect and avoid virtualization and analysis environments.
references:
    - https://www.loobins.io/binaries/sysctl/#
    - https://evasions.checkpoint.com/techniques/macos.html
    - https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
    - https://www.sentinelone.com/labs/20-common-tools-techniques-used-by-macos-threat-actors-malware/
    - https://objective-see.org/blog/blog_0x1E.html
    - https://www.virustotal.com/gui/file/1c547a064494a35d6b5e6b459de183ab2720a22725e082bed6f6629211f7abc1/behavior
    - https://www.virustotal.com/gui/file/b4b1fc65f87b3dcfa35e2dbe8e0a34ad9d8a400bec332025c0a2e200671038aa/behavior
author: Pratinav Chandra
date: 2024-05-27
tags:
    - attack.defense-evasion
    - attack.t1497.001
    - attack.discovery
    - attack.t1082
logsource:
    product: macos
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '/sysctl'
        - CommandLine|contains: 'sysctl'
    selection_cmd:
        CommandLine|contains:
            - 'hw.'
            - 'kern.'
            - 'machdep.'
    condition: all of selection_*
falsepositives:
    - Legitimate administrative activities
level: medium
```
