```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\curl.exe" or tgt.process.displayName="The curl executable"))
```


# Original Sigma Rule:
```yaml
title: Curl.EXE Execution
id: bbeaed61-1990-4773-bf57-b81dbad7db2d
related:
    - id: e218595b-bbe7-4ee5-8a96-f32a24ad3468 # Suspicious curl execution
      type: derived
status: test
description: Detects a curl process start on Windows, which could indicates a file download from a remote location or a simple web request to a remote server
references:
    - https://web.archive.org/web/20200128160046/https://twitter.com/reegun21/status/1222093798009790464
author: Florian Roth (Nextron Systems)
date: 2022-07-05
modified: 2023-02-21
tags:
    - attack.command-and-control
    - attack.t1105
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\curl.exe'
        - Product: 'The curl executable'
    condition: selection
falsepositives:
    - Scripts created by developers and admins
    - Administrative activity
level: low
```
