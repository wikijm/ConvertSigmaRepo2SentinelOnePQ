```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\desktopimgdownldr.exe" and src.process.image.path contains "\desktopimgdownldr.exe" and tgt.process.cmdline contains "/lockscreenurl:http"))
```


# Original Sigma Rule:
```yaml
title: Remote File Download Via Desktopimgdownldr Utility
id: 214641c2-c579-4ecb-8427-0cf19df6842e
status: test
description: Detects the desktopimgdownldr utility being used to download a remote file. An adversary may use desktopimgdownldr to download arbitrary files as an alternative to certutil.
references:
    - https://www.elastic.co/guide/en/security/current/remote-file-download-via-desktopimgdownldr-utility.html
author: Tim Rauch, Elastic (idea)
date: 2022-09-27
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\desktopimgdownldr.exe'
        ParentImage|endswith: '\desktopimgdownldr.exe'
        CommandLine|contains: '/lockscreenurl:http'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
