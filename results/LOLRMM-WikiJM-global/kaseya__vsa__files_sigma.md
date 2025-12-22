```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "%localappdata%\\Kaseya\\Log\\KaseyaLiveConnect\*" or tgt.file.path contains "~/Library/Logs/com.kaseya/KaseyaLiveConnect/" or tgt.file.path contains "C:\\ProgramData\\Kaseya\\Log\\Endpoint\*" or tgt.file.path="*C:\\Program Files*\\Kaseya\*\\agentmon.log" or tgt.file.path contains "/var/log/system.log" or tgt.file.path="* ~/opt/kaseya/*/logs*" or tgt.file.path contains "C:\\Users\*\\AppData\\Local\\Temp\\KASetup.log" or tgt.file.path contains "C:\\Windows\\Temp\\KASetup.log" or tgt.file.path contains "C:\\ProgramData\\Kaseya\\Log\\KaseyaEdgeServices\*" or tgt.file.path contains "C:\\Kaseya\\api\\v1.0\\logs\\" or tgt.file.path contains "C:\\Kaseya\\api\\v1.5\\endpoint\\logs" or tgt.file.path contains "C:\\Kaseya\\api\\v1.5\\endpoints\\logs" or tgt.file.path contains "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Kaseya\\Log\\MakeSelfSignedCert.exe\\" or tgt.file.path contains "C:\\Kaseya\\WebPages\\install\\makecert.txt" or tgt.file.path="*C:\\ProgramData\\Kaseya\\Log\\Endpoint\\Instance_*\\KaseyaEndpoint*" or tgt.file.path="*C:\\ProgramData\\Kaseya\\Log\\Endpoint\\Instance_*\\Session_*"))
```


# Original Sigma Rule:
```yaml
title: Potential Kaseya (VSA) RMM Tool File Activity
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
    - '%localappdata%\Kaseya\Log\KaseyaLiveConnect\*'
    - ~/Library/Logs/com.kaseya/KaseyaLiveConnect/*
    - C:\ProgramData\Kaseya\Log\Endpoint\*
    - C:\Program Files*\Kaseya\*\agentmon.log
    - /var/log/system.log
    - ' ~/opt/kaseya/*/logs*'
    - C:\Users\*\AppData\Local\Temp\KASetup.log
    - C:\Windows\Temp\KASetup.log
    - C:\ProgramData\Kaseya\Log\KaseyaEdgeServices\*
    - C:\Kaseya\api\v1.0\logs\
    - C:\Kaseya\api\v1.5\endpoint\logs
    - C:\Kaseya\api\v1.5\endpoints\logs
    - C:\Windows\System32\config\systemprofile\AppData\Local\Kaseya\Log\MakeSelfSignedCert.exe\
    - C:\Kaseya\WebPages\install\makecert.txt
    - C:\ProgramData\Kaseya\Log\Endpoint\Instance_*\KaseyaEndpoint*
    - C:\ProgramData\Kaseya\Log\Endpoint\Instance_*\Session_*
  condition: selection
id: 6d887504-0f57-484a-ad7f-9479291eccd1
status: experimental
description: Detects potential files activity of Kaseya (VSA) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Kaseya (VSA)
level: medium
```
