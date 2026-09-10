```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\tmagentsvc.exe" or tgt.process.image.path contains "\\tmagentsvc.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Teramind RMM Tool Process Activity
id: 7c5595f4-0a03-5744-bdb7-fb951cd62fe2
status: experimental
description: |
    Detects potential processes activity of Teramind RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: '\\tmagentsvc.exe'
    selection_image:
        Image|endswith: '\\tmagentsvc.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Teramind
level: medium
```
