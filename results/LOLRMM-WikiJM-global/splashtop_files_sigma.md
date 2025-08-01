```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\windows\System32\winevt\Logs\Splashtop-Splashtop Streamer-Status%4Operational.evtx" or tgt.file.path contains "C:\windows\System32\winevt\Logs\Splashtop-Splashtop Streamer-Remote Session%4Operational.evtx" or tgt.file.path contains "%PROGRAMDATA%\Splashtop\Temp\log\FTCLog.txt" or tgt.file.path contains "C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\agent_log.txt" or tgt.file.path contains "C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\SPLog.txt" or tgt.file.path contains "C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\svcinfo.txt" or tgt.file.path contains "C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\sysinfo.txt" or tgt.file.path contains "C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRService.exe" or tgt.file.path contains "C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRAgent.exe" or tgt.file.path contains "C:\Program Files (x86)\Splashtop\Splashtop Software Updater\SSUAgent.exe" or tgt.file.path contains "C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRUtility.exe" or tgt.file.path contains "C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRFeature.exe" or tgt.file.path contains "C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\db\SRAgent.sqlite3"))
```


# Original Sigma Rule:
```yaml
title: Potential Splashtop RMM Tool File Activity
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
    - C:\windows\System32\winevt\Logs\Splashtop-Splashtop Streamer-Status%4Operational.evtx
    - C:\windows\System32\winevt\Logs\Splashtop-Splashtop Streamer-Remote Session%4Operational.evtx
    - '%PROGRAMDATA%\Splashtop\Temp\log\FTCLog.txt'
    - C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\agent_log.txt
    - C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\SPLog.txt
    - C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\svcinfo.txt
    - C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\sysinfo.txt
    - C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRService.exe
    - C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRAgent.exe
    - C:\Program Files (x86)\Splashtop\Splashtop Software Updater\SSUAgent.exe
    - C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRUtility.exe
    - C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRFeature.exe
    - C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\db\SRAgent.sqlite3
  condition: selection
id: 4281fc0d-d007-4455-93a4-c74479a91204
status: experimental
description: Detects potential files activity of Splashtop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Splashtop
level: medium
```
