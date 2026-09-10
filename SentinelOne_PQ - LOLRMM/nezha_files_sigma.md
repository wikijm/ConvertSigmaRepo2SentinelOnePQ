```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\nezha\\nezha-agent.exe" or tgt.file.path contains "C:\\nezha\\config.yml" or tgt.file.path contains "/opt/nezha/agent/nezha-agent" or tgt.file.path contains "/opt/nezha/agent/config.yml" or tgt.file.path contains "/etc/systemd/system/nezha-agent.service" or tgt.file.path contains "/opt/nezha/dashboard/app"))
```


# Original Sigma Rule:
```yaml
title: Potential Nezha RMM Tool File Activity
id: 839c690f-219f-5c91-ba0c-d0f5a62a7052
status: experimental
description: |
    Detects potential files activity of Nezha RMM tool
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
            - 'C:\nezha\nezha-agent.exe'
            - 'C:\nezha\config.yml'
            - '/opt/nezha/agent/nezha-agent'
            - '/opt/nezha/agent/config.yml'
            - '/etc/systemd/system/nezha-agent.service'
            - '/opt/nezha/dashboard/app'
    condition: selection
falsepositives:
    - Legitimate use of Nezha
level: medium
```
