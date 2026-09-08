```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "%localappdata%\\Kaseya\\Log\\KaseyaLiveConnect\*" or tgt.file.path contains "~/Library/Logs/com.kaseya/KaseyaLiveConnect/" or tgt.file.path contains "C:\\ProgramData\\Kaseya\\Log\\Endpoint\*" or tgt.file.path="*C:\\Program Files*\\Kaseya\*\\agentmon.log" or tgt.file.path contains "/var/log/system.log" or tgt.file.path="* ~/opt/kaseya/*/logs*" or tgt.file.path contains "C:\\Users\*\\AppData\\Local\\Temp\\KASetup.log" or tgt.file.path contains "C:\\Windows\\Temp\\KASetup.log" or tgt.file.path contains "C:\\ProgramData\\Kaseya\\Log\\KaseyaEdgeServices\*" or tgt.file.path contains "C:\\Kaseya\\api\\v1.0\\logs\\" or tgt.file.path contains "C:\\Kaseya\\api\\v1.5\\endpoint\\logs" or tgt.file.path contains "C:\\Kaseya\\api\\v1.5\\endpoints\\logs" or tgt.file.path contains "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Kaseya\\Log\\MakeSelfSignedCert.exe\\" or tgt.file.path contains "C:\\Kaseya\\WebPages\\install\\makecert.txt" or tgt.file.path="*C:\\ProgramData\\Kaseya\\Log\\Endpoint\\Instance_*\\KaseyaEndpoint*" or tgt.file.path="*C:\\ProgramData\\Kaseya\\Log\\Endpoint\\Instance_*\\Session_*"))
```


# Original Sigma Rule:
```yaml
title: Potential Kaseya (VSA) RMM Tool File Activity
id: 946d8fc9-9de3-40d6-b9dd-ffbfcf803f06
status: experimental
description: |
    Detects potential files activity of Kaseya (VSA) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
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
            - '%localappdata%\Kaseya\Log\KaseyaLiveConnect\*'
            - '~/Library/Logs/com.kaseya/KaseyaLiveConnect/*'
            - 'C:\ProgramData\Kaseya\Log\Endpoint\*'
            - 'C:\Program Files*\Kaseya\*\agentmon.log'
            - '/var/log/system.log'
            - ' ~/opt/kaseya/*/logs*'
            - 'C:\Users\*\AppData\Local\Temp\KASetup.log'
            - 'C:\Windows\Temp\KASetup.log'
            - 'C:\ProgramData\Kaseya\Log\KaseyaEdgeServices\*'
            - 'C:\Kaseya\api\v1.0\logs\'
            - 'C:\Kaseya\api\v1.5\endpoint\logs'
            - 'C:\Kaseya\api\v1.5\endpoints\logs'
            - 'C:\Windows\System32\config\systemprofile\AppData\Local\Kaseya\Log\MakeSelfSignedCert.exe\'
            - 'C:\Kaseya\WebPages\install\makecert.txt'
            - 'C:\ProgramData\Kaseya\Log\Endpoint\Instance_*\KaseyaEndpoint*'
            - 'C:\ProgramData\Kaseya\Log\Endpoint\Instance_*\Session_*'
    condition: selection
falsepositives:
    - Legitimate use of Kaseya (VSA)
level: medium
```
