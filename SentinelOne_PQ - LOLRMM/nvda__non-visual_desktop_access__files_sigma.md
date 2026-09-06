```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\NVDA\\nvda.exe" or tgt.file.path contains "C:\\Program Files\\NVDA\\nvda.exe" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\nvda\\nvda.log" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\nvda\\nvda.ini"))
```


# Original Sigma Rule:
```yaml
title: Potential NVDA (Non-Visual Desktop Access) RMM Tool File Activity
id: 26110593-ccfd-510a-9d00-a877daa2ee99
status: experimental
description: |
    Detects potential files activity of NVDA (Non-Visual Desktop Access) RMM tool
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
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files (x86)\NVDA\nvda.exe'
            - 'C:\Program Files\NVDA\nvda.exe'
            - 'C:\Users\*\AppData\Roaming\nvda\nvda.log'
            - 'C:\Users\*\AppData\Roaming\nvda\nvda.ini'
    condition: selection
falsepositives:
    - Legitimate use of NVDA (Non-Visual Desktop Access)
level: medium
```
