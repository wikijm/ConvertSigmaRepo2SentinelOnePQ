```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageRunCommandInteractive\\log.txt" or tgt.file.path contains "C:\\Program Files\\ATERA Networks\\AteraAgent\\Packages\*" or tgt.file.path contains "C:\\Program Files\\ATERA Networks\\AteraAgent\\AteraAgent.exe" or tgt.file.path contains "C:\\Program Files\\Atera Networks\\AlphaAgent.exe" or tgt.file.path contains "C:\\Program Files\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageSTRemote\\AgentPackageSTRemote.exe" or tgt.file.path contains "C:\\Program Files\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageMonitoring\\AgentPackageMonitoring.exe" or tgt.file.path contains "C:\\Program Files\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageHeartbeat\\AgentPackageHeartbeat.exe" or tgt.file.path contains "C:\\Program Files\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageFileExplorer\\AgentPackageFileExplorer.exe" or tgt.file.path contains "C:\\Program Files\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageRunCommandInteractive\\AgentPackageRunCommandInteractive.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Atera RMM Tool File Activity
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
    - C:\Program Files\ATERA Networks\AteraAgent\Packages\AgentPackageRunCommandInteractive\log.txt
    - C:\Program Files\ATERA Networks\AteraAgent\Packages\*
    - C:\Program Files\ATERA Networks\AteraAgent\AteraAgent.exe
    - C:\Program Files\Atera Networks\AlphaAgent.exe
    - C:\Program Files\ATERA Networks\AteraAgent\Packages\AgentPackageSTRemote\AgentPackageSTRemote.exe
    - C:\Program Files\ATERA Networks\AteraAgent\Packages\AgentPackageMonitoring\AgentPackageMonitoring.exe
    - C:\Program Files\ATERA Networks\AteraAgent\Packages\AgentPackageHeartbeat\AgentPackageHeartbeat.exe
    - C:\Program Files\ATERA Networks\AteraAgent\Packages\AgentPackageFileExplorer\AgentPackageFileExplorer.exe
    - C:\Program Files\ATERA Networks\AteraAgent\Packages\AgentPackageRunCommandInteractive\AgentPackageRunCommandInteractive.exe
  condition: selection
id: a08c1267-edce-4af3-8f48-bf74bb4f52c6
status: experimental
description: Detects potential files activity of Atera RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Atera
level: medium
```
