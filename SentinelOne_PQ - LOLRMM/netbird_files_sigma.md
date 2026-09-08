```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\Netbird\\netbird.exe" or tgt.file.path contains "C:\\ProgramData\\Netbird\\config.json" or tgt.file.path contains "/etc/netbird/config.json" or tgt.file.path contains "/var/log/netbird/" or tgt.file.path contains "/etc/netbird/install.conf" or tgt.file.path contains "/Applications/NetBird UI.app" or tgt.file.path contains "C:\\bin\\netbird.msi" or tgt.file.path contains "C:\\bin\\OpenSSH.msi" or tgt.file.path contains "C:\\bin\\cis.vbs" or tgt.file.path contains "C:\\bin\\trm.zip" or tgt.file.path contains "C:\\temper\\trm"))
```


# Original Sigma Rule:
```yaml
title: Potential NetBird RMM Tool File Activity
id: d7450e11-72aa-57b4-b835-9afeaa6eb423
status: experimental
description: |
    Detects potential files activity of NetBird RMM tool
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
            - 'C:\Program Files\Netbird\netbird.exe'
            - 'C:\ProgramData\Netbird\config.json'
            - '/etc/netbird/config.json'
            - '/var/log/netbird/*'
            - '/etc/netbird/install.conf'
            - '/Applications/NetBird UI.app'
            - 'C:\bin\netbird.msi'
            - 'C:\bin\OpenSSH.msi'
            - 'C:\bin\cis.vbs'
            - 'C:\bin\trm.zip'
            - 'C:\temper\trm'
    condition: selection
falsepositives:
    - Legitimate use of NetBird
level: medium
```
