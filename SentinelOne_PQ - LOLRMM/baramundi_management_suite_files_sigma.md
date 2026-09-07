```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
event.category="file" and (endpoint.os="windows" and tgt.file.path contains "C:\\Program Files\\bsag\\bma\\bma.exe")
```


# Original Sigma Rule:
```yaml
title: Potential baramundi Management Suite RMM Tool File Activity
id: 999f157a-b11a-5b19-bde9-4dd581031cb2
status: experimental
description: |
    Detects potential files activity of baramundi Management Suite RMM tool
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
        TargetFilename|endswith: 'C:\Program Files\bsag\bma\bma.exe'
    condition: selection
falsepositives:
    - Legitimate use of baramundi Management Suite
level: medium
```
