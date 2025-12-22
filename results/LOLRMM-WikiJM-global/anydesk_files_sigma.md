```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "%programdata%\\AnyDesk\\ad_svc.trace" or tgt.file.path contains "%programdata%\\AnyDesk\\connection_trace.txt" or tgt.file.path contains "%APPDATA%\\AnyDesk\\connection_trace.txt" or tgt.file.path contains "%APPDATA%\\AnyDesk\\ad.trace" or tgt.file.path contains "%APPDATA%\\AnyDesk\\chat\*.txt" or tgt.file.path contains "%APPDATA%\\AnyDesk\\user.conf" or tgt.file.path contains "%PROGRAMDATA%\\AnyDesk\\service.conf" or tgt.file.path contains "%APPDATA%\\AnyDesk\\service.conf" or tgt.file.path contains "%APPDATA%\\AnyDesk\\system.conf" or tgt.file.path contains "%PROGRAMDATA%\\AnyDesk\\system.conf" or tgt.file.path contains "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\AnyDesk.lnk" or tgt.file.path contains "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\AnyDesk\\Uninstall AnyDesk.lnk" or tgt.file.path contains "C:\\Users\*\\Videos\\AnyDesk\*.anydesk" or tgt.file.path contains "C:\\Windows\\SysWOW64\\config\\systemprofile\\AppData\\Roaming\\AnyDesk\*" or tgt.file.path contains "~/Library/Application Support/AnyDesk/Logs/" or tgt.file.path contains "~/.config/AnyDesk/Logs/"))
```


# Original Sigma Rule:
```yaml
title: Potential AnyDesk RMM Tool File Activity
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
    - '%programdata%\AnyDesk\ad_svc.trace'
    - '%programdata%\AnyDesk\connection_trace.txt'
    - '%APPDATA%\AnyDesk\connection_trace.txt'
    - '%APPDATA%\AnyDesk\ad.trace'
    - '%APPDATA%\AnyDesk\chat\*.txt'
    - '%APPDATA%\AnyDesk\user.conf'
    - '%PROGRAMDATA%\AnyDesk\service.conf'
    - '%APPDATA%\AnyDesk\service.conf'
    - '%APPDATA%\AnyDesk\system.conf'
    - '%PROGRAMDATA%\AnyDesk\system.conf'
    - '%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp\AnyDesk.lnk'
    - '%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\AnyDesk\Uninstall AnyDesk.lnk'
    - C:\Users\*\Videos\AnyDesk\*.anydesk
    - C:\Windows\SysWOW64\config\systemprofile\AppData\Roaming\AnyDesk\*
    - ~/Library/Application Support/AnyDesk/Logs/
    - ~/.config/AnyDesk/Logs/
  condition: selection
id: 20ebd46b-44ea-4679-9563-ca9b6b4d75e0
status: experimental
description: Detects potential files activity of AnyDesk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of AnyDesk
level: medium
```
