```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((not tgt.process.image.path contains "\\") and (not (not (tgt.process.image.path matches "\.*") or (tgt.process.image.path in ("-","")) or ((tgt.process.image.path in ("System","Registry","MemCompression","vmmem")) or (tgt.process.cmdline in ("Registry","MemCompression","vmmem")))))))
```


# Original Sigma Rule:
```yaml
title: Execution Of Non-Existing File
id: 71158e3f-df67-472b-930e-7d287acaa3e1
status: test
description: Checks whether the image specified in a process creation event is not a full, absolute path (caused by process ghosting or other unorthodox methods to start a process)
references:
    - https://pentestlaboratories.com/2021/12/08/process-ghosting/
author: Max Altgelt (Nextron Systems)
date: 2021-12-09
modified: 2022-12-14
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    image_absolute_path:
        Image|contains: '\'
    filter_null:
        Image: null
    filter_empty:
        Image:
            - '-'
            - ''
    filter_4688:
        - Image:
              - 'System'
              - 'Registry'
              - 'MemCompression'
              - 'vmmem'
        - CommandLine:
              - 'Registry'
              - 'MemCompression'
              - 'vmmem'
    condition: not image_absolute_path and not 1 of filter*
falsepositives:
    - Unknown
level: high
```
