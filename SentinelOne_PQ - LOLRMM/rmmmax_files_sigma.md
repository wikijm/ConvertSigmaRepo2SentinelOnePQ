```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "%ProgramData%\\rmmmax\\AgentService\\RMMmaxAgentService.exe" or tgt.file.path contains "%ProgramData%\\RMMmax\\AgentService\\activity.log" or tgt.file.path="*%SystemRoot%\\Temp\\rmmmax_*.ps1" or tgt.file.path contains "/var/rmmmax/agentservice/rmmmax_agent.py" or tgt.file.path contains "/usr/local/bin/rmmmax-agent" or tgt.file.path contains "/etc/systemd/system/rmmmax-agent.service" or tgt.file.path contains "/var/rmmmax/agentservice/config.json" or tgt.file.path contains "/var/rmmmax/agentservice/activity.log" or tgt.file.path contains "/Applications/RMMmax Agent.app/Contents/MacOS/RMMmax Agent" or tgt.file.path contains "/Library/LaunchDaemons/com.rmmmax.agentservice.plist" or tgt.file.path contains "/Library/LaunchAgents/com.rmmmax.agentui.plist" or tgt.file.path contains "/var/rmmmax/agentservice/state.json"))
```


# Original Sigma Rule:
```yaml
title: Potential RMMmax RMM Tool File Activity
id: 92e0c6f8-253a-5755-b0f8-b4155ab9f949
status: experimental
description: |
    Detects potential files activity of RMMmax RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-09
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '%ProgramData%\rmmmax\AgentService\RMMmaxAgentService.exe'
            - '%ProgramData%\RMMmax\AgentService\activity.log'
            - '%SystemRoot%\Temp\rmmmax_*.ps1'
            - '/var/rmmmax/agentservice/rmmmax_agent.py'
            - '/usr/local/bin/rmmmax-agent'
            - '/etc/systemd/system/rmmmax-agent.service'
            - '/var/rmmmax/agentservice/config.json'
            - '/var/rmmmax/agentservice/activity.log'
            - '/Applications/RMMmax Agent.app/Contents/MacOS/RMMmax Agent'
            - '/Library/LaunchDaemons/com.rmmmax.agentservice.plist'
            - '/Library/LaunchAgents/com.rmmmax.agentui.plist'
            - '/var/rmmmax/agentservice/state.json'
    condition: selection
falsepositives:
    - Legitimate use of RMMmax
level: medium
```
