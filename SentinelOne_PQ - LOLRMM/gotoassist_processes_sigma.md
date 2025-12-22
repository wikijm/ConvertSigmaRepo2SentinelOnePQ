```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "gotoassist.exe" or src.process.image.path="*g2a*.exe" or src.process.image.path contains "GoTo Assist Opener.exe" or src.process.image.path contains "g2mcomm.exe" or src.process.image.path contains "goto opener.exe" or src.process.image.path contains "g2ax_comm_customer.exe") or (tgt.process.image.path contains "gotoassist.exe" or tgt.process.image.path="*g2a*.exe" or tgt.process.image.path contains "GoTo Assist Opener.exe" or tgt.process.image.path contains "g2mcomm.exe" or tgt.process.image.path contains "goto opener.exe" or tgt.process.image.path contains "g2ax_comm_customer.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential GoToAssist RMM Tool Process Activity
id: 7e3932cf-416c-4e30-a60d-c4582183b355
status: experimental
description: |
    Detects potential processes activity of GoToAssist RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - gotoassist.exe
            - g2a*.exe
            - GoTo Assist Opener.exe
            - g2mcomm.exe
            - goto opener.exe
            - g2ax_comm_customer.exe
    selection_image:
        Image|endswith:
            - gotoassist.exe
            - g2a*.exe
            - GoTo Assist Opener.exe
            - g2mcomm.exe
            - goto opener.exe
            - g2ax_comm_customer.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of GoToAssist
level: medium
```
