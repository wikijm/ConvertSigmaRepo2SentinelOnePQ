```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/hdiutil" and (tgt.process.cmdline contains "attach " or tgt.process.cmdline contains "mount ")))
```


# Original Sigma Rule:
```yaml
title: Disk Image Mounting Via Hdiutil - MacOS
id: bf241472-f014-4f01-a869-96f99330ca8c
status: test
description: Detects the execution of the hdiutil utility in order to mount disk images.
references:
    - https://www.loobins.io/binaries/hdiutil/
    - https://www.sentinelone.com/blog/from-the-front-linesunsigned-macos-orat-malware-gambles-for-the-win/
    - https://ss64.com/mac/hdiutil.html
author: Omar Khaled (@beacon_exe)
date: 2024-08-10
tags:
    - attack.initial-access
    - attack.collection
    - attack.t1566.001
    - attack.t1560.001
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: /hdiutil
        CommandLine|contains:
            - 'attach '
            - 'mount '
    condition: selection
falsepositives:
    - Legitimate usage of hdiutil by administrators and users.
level: medium
```
