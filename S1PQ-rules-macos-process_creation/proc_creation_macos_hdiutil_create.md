```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/hdiutil" and tgt.process.cmdline contains "create"))
```


# Original Sigma Rule:
```yaml
title: Disk Image Creation Via Hdiutil - MacOS
id: 1cf98dc2-fcb0-47c9-8aea-654c9284d1ae
status: test
description: Detects the execution of the hdiutil utility in order to create a disk image.
references:
    - https://www.loobins.io/binaries/hdiutil/
    - https://www.sentinelone.com/blog/from-the-front-linesunsigned-macos-orat-malware-gambles-for-the-win/
    - https://ss64.com/mac/hdiutil.html
author: Omar Khaled (@beacon_exe)
date: 2024-08-10
tags:
    - attack.exfiltration
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: /hdiutil
        CommandLine|contains: 'create'
    condition: selection
falsepositives:
    - Legitimate usage of hdiutil by administrators and users.
level: medium
```
