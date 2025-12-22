```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "TaniumClient.exe" or src.process.image.path contains "TaniumCX.exe" or src.process.image.path contains "TaniumExecWrapper.exe" or src.process.image.path contains "TaniumFileInfo.exe" or src.process.image.path contains "TPowerShell.exe") or (tgt.process.image.path contains "TaniumClient.exe" or tgt.process.image.path contains "TaniumCX.exe" or tgt.process.image.path contains "TaniumExecWrapper.exe" or tgt.process.image.path contains "TaniumFileInfo.exe" or tgt.process.image.path contains "TPowerShell.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Tanium RMM Tool Process Activity
id: 3ed81efb-a88a-48df-a65e-eeae644b4dd9
status: experimental
description: |
    Detects potential processes activity of Tanium RMM tool
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
            - TaniumClient.exe
            - TaniumCX.exe
            - TaniumExecWrapper.exe
            - TaniumFileInfo.exe
            - TPowerShell.exe
    selection_image:
        Image|endswith:
            - TaniumClient.exe
            - TaniumCX.exe
            - TaniumExecWrapper.exe
            - TaniumFileInfo.exe
            - TPowerShell.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Tanium
level: medium
```
