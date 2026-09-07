```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "weClipboardListener.exe" or tgt.file.path contains "bbl.exe" or tgt.file.path contains "weprtct.exe" or tgt.file.path contains "wemonc.exe" or tgt.file.path contains "wesvc.exe" or tgt.file.path contains "libeay32.dll" or tgt.file.path contains "ssleay32.dll" or tgt.file.path="*wec_launcher_[a-Z0-9]*_.exe" or tgt.file.path="*wec_launcher_[a-Z0-9]*_.pkg" or tgt.file.path contains "weInstSvc.exe" or tgt.file.path contains "C:\\ProgramData\\{E0E95C6C-F194-4846-928D-E5538022226D}\\"))
```


# Original Sigma Rule:
```yaml
title: Potential Controlio RMM Tool File Activity
id: 714949ba-7d7d-56c4-be3f-7ced6723846e
status: experimental
description: |
    Detects potential files activity of Controlio RMM tool
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
            - 'weClipboardListener.exe'
            - 'bbl.exe'
            - 'weprtct.exe'
            - 'wemonc.exe'
            - 'wesvc.exe'
            - 'libeay32.dll'
            - 'ssleay32.dll'
            - 'wec_launcher_[a-Z0-9]*_.exe'
            - 'wec_launcher_[a-Z0-9]*_.pkg'
            - 'weInstSvc.exe'
            - 'C:\ProgramData\{E0E95C6C-F194-4846-928D-E5538022226D}\'
    condition: selection
falsepositives:
    - Legitimate use of Controlio
level: medium
```
