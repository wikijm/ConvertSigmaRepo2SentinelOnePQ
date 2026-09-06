```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\Techinline Ltd\\SetMe Unattended\\Client\\SetMe_Client.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Techinline Ltd\\SetMe Unattended\\Module\*\\tinUnattendedModule.exe" or tgt.file.path="*C:\\Users\*\\AppData\\Local\\Temp\\tinClientExtractor-*\\tinClientDesktopApplication.exe" or tgt.file.path="*C:\\Users\*\\AppData\\Local\\Temp\\tinClientExtractor-*\\tinClientSessionManager.exe" or tgt.file.path contains "C:\\ProgramData\\Techinline Ltd\\settings.ini" or tgt.file.path contains "C:\\ProgramData\\SetMe Client" or tgt.file.path contains "C:\\Windows\\Temp\\setme\\Sentry\*"))
```


# Original Sigma Rule:
```yaml
title: Potential SetMe PRO RMM Tool File Activity
id: 066f29bb-0624-5af9-b492-0da14b655b29
status: experimental
description: |
    Detects potential files activity of SetMe PRO RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-02
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
            - 'C:\Program Files (x86)\Techinline Ltd\SetMe Unattended\Client\SetMe_Client.exe'
            - 'C:\Program Files (x86)\Techinline Ltd\SetMe Unattended\Module\*\tinUnattendedModule.exe'
            - 'C:\Users\*\AppData\Local\Temp\tinClientExtractor-*\tinClientDesktopApplication.exe'
            - 'C:\Users\*\AppData\Local\Temp\tinClientExtractor-*\tinClientSessionManager.exe'
            - 'C:\ProgramData\Techinline Ltd\settings.ini*'
            - 'C:\ProgramData\SetMe Client'
            - 'C:\Windows\Temp\setme\Sentry\*'
    condition: selection
falsepositives:
    - Legitimate use of SetMe PRO
level: medium
```
