```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*support-logmeinrescue*.exe" or src.process.image.path contains "support-logmeinrescue.exe" or src.process.image.path contains "lmi_rescue.exe" or src.process.image.path contains "lmi_rescue.exe" or src.process.image.path contains "lmi_rescue_srv.exe" or src.process.image.path contains "lmi_rescue.exe") or (tgt.process.image.path="*support-logmeinrescue*.exe" or tgt.process.image.path contains "support-logmeinrescue.exe" or tgt.process.image.path contains "lmi_rescue.exe" or tgt.process.image.path contains "lmi_rescue.exe" or tgt.process.image.path contains "lmi_rescue_srv.exe" or tgt.process.image.path contains "lmi_rescue.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential LogMeIn rescue RMM Tool Process Activity
id: 10e05dda-0352-4bd9-a415-00d7cb5791e7
status: experimental
description: |
    Detects potential processes activity of LogMeIn rescue RMM tool
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
            - support-logmeinrescue*.exe
            - support-logmeinrescue.exe
            - lmi_rescue.exe
            - lmi_rescue.exe
            - lmi_rescue_srv.exe
            - lmi_rescue.exe
    selection_image:
        Image|endswith:
            - support-logmeinrescue*.exe
            - support-logmeinrescue.exe
            - lmi_rescue.exe
            - lmi_rescue.exe
            - lmi_rescue_srv.exe
            - lmi_rescue.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of LogMeIn rescue
level: medium
```
