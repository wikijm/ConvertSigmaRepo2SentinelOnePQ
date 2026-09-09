```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\Monitic\\agent.exe" or tgt.file.path contains "C:\\Program Files\\Monitic\\amon.exe" or tgt.file.path contains "C:\\Program Files\\Monitic\\conf.json" or tgt.file.path contains "C:\\Program Files\\Monitic\*" or tgt.file.path contains "%USERPROFILE%\\Desktop\\MoniticInstaller.exe" or tgt.file.path contains "%TEMP%\*\\agent_installer.bat" or tgt.file.path contains "%TEMP%\*\\amon.exe" or tgt.file.path contains "%TEMP%\*\\agent.exe" or tgt.file.path contains "%CD%\\installer.zip" or tgt.file.path contains "%CD%\\conf.json"))
```


# Original Sigma Rule:
```yaml
title: Potential Monitic RMM Tool File Activity
id: 452612fb-7676-5d3b-bafe-9c5a3393855f
status: experimental
description: |
    Detects potential files activity of Monitic RMM tool
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
            - 'C:\Program Files\Monitic\agent.exe'
            - 'C:\Program Files\Monitic\amon.exe'
            - 'C:\Program Files\Monitic\conf.json'
            - 'C:\Program Files\Monitic\*'
            - '%USERPROFILE%\Desktop\MoniticInstaller.exe'
            - '%TEMP%\*\agent_installer.bat'
            - '%TEMP%\*\amon.exe'
            - '%TEMP%\*\agent.exe'
            - '%CD%\installer.zip'
            - '%CD%\conf.json'
    condition: selection
falsepositives:
    - Legitimate use of Monitic
level: medium
```
