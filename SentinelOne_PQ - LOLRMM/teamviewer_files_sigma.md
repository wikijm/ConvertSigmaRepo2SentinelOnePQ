```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Users\\<username>\\AppData\\Local\\Temp\\TeamViewer\\TV15Install.log" or tgt.file.path contains "TeamViewer\\d\\d_Logfile\\.log" or tgt.file.path contains "C:\\Program Files\\TeamViewer\\Connections_incoming.txt" or tgt.file.path contains "C:\\Program Files\\TeamViewer\\TVNetwork.log" or tgt.file.path contains "%LOCALAPPDATA%\\Temp\\TeamViewer\\TV15Install.log" or tgt.file.path contains "%APPDATA%\\TeamViewer\\TeamViewer\\d\\d_Logfile\\.log" or tgt.file.path contains "teamviewerqs.exe" or tgt.file.path contains "tv_w32.exe" or tgt.file.path contains "tv_w64.exe" or tgt.file.path contains "tv_x64.exe" or tgt.file.path contains "teamviewer.exe" or tgt.file.path contains "teamviewer_service.exe" or tgt.file.path contains "%LOCALAPPDATA%\\TeamViewer\\Database\\tvchatfilecache.db" or tgt.file.path contains "%LOCALAPPDATA%\\TeamViewer\\RemotePrinting\\tvprint.db" or tgt.file.path contains "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\TeamViewer.lnk" or tgt.file.path="*C:\\Program Files*\\TeamViewer\\connections*.txt" or tgt.file.path contains "C:\\Users\*\\AppData\\Roaming\\TeamViewer\\MRU\\RemoteSupport\*tvc"))
```


# Original Sigma Rule:
```yaml
title: Potential TeamViewer RMM Tool File Activity
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
    - C:\Users\<username>\AppData\Local\Temp\TeamViewer\TV15Install.log
    - TeamViewer\d\d_Logfile\.log
    - C:\Program Files\TeamViewer\Connections_incoming.txt
    - C:\Program Files\TeamViewer\TVNetwork.log
    - '%LOCALAPPDATA%\Temp\TeamViewer\TV15Install.log'
    - '%APPDATA%\\TeamViewer\\TeamViewer\d\d_Logfile\.log'
    - teamviewerqs.exe
    - tv_w32.exe
    - tv_w64.exe
    - tv_x64.exe
    - teamviewer.exe
    - teamviewer_service.exe
    - '%LOCALAPPDATA%\TeamViewer\Database\tvchatfilecache.db'
    - '%LOCALAPPDATA%\TeamViewer\RemotePrinting\tvprint.db'
    - '%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\TeamViewer.lnk'
    - C:\Program Files*\TeamViewer\connections*.txt
    - C:\Users\*\AppData\Roaming\TeamViewer\MRU\RemoteSupport\*tvc
  condition: selection
id: a690575f-3b07-494b-8783-2ab290a28275
status: experimental
description: Detects potential files activity of TeamViewer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of TeamViewer
level: medium
```
