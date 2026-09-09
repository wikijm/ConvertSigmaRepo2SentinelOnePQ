```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "\\ControlR.Agent.Installer.exe" or tgt.file.path contains "C:\\Program Files\\ControlR\*\\ControlR.Agent.exe" or tgt.file.path contains "C:\\ProgramData\\ControlR\*\\appsettings.json" or tgt.file.path="*C:\\ProgramData\\ControlR\*\\Logs\\ControlR.Agent\\LogFile*.log" or tgt.file.path="*C:\\ProgramData\\ControlR\*\\Logs\\ControlR.DesktopClient\\LogFile*.log" or tgt.file.path="*/usr/local/bin/ControlR/*/ControlR.Agent" or tgt.file.path="*/etc/controlr/*/appsettings.json" or tgt.file.path="*/etc/systemd/system/controlr.agent*.service" or tgt.file.path="*/var/log/controlr/*/ControlR.Agent/LogFile*.log" or tgt.file.path="*~/.controlr/*/logs/ControlR.Agent/LogFile*.log" or tgt.file.path="*/Library/Application Support/ControlR/*/ControlR.Agent" or tgt.file.path contains "/Applications/ControlR.app" or tgt.file.path="*/Applications/ControlR.*.app" or tgt.file.path="*/Library/LaunchDaemons/app.controlr.agent*.plist" or tgt.file.path="*/Library/LaunchAgents/app.controlr.desktop*.plist"))
```


# Original Sigma Rule:
```yaml
title: Potential ControlR RMM Tool File Activity
id: b2e670c3-2d33-5772-9fc4-1252ee6126ae
status: experimental
description: |
    Detects potential files activity of ControlR RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-08-18
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
            - '*\ControlR.Agent.Installer.exe'
            - 'C:\Program Files\ControlR\*\ControlR.Agent.exe'
            - 'C:\ProgramData\ControlR\*\appsettings.json'
            - 'C:\ProgramData\ControlR\*\Logs\ControlR.Agent\LogFile*.log'
            - 'C:\ProgramData\ControlR\*\Logs\ControlR.DesktopClient\LogFile*.log'
            - '/usr/local/bin/ControlR/*/ControlR.Agent'
            - '/etc/controlr/*/appsettings.json'
            - '/etc/systemd/system/controlr.agent*.service'
            - '/var/log/controlr/*/ControlR.Agent/LogFile*.log'
            - '~/.controlr/*/logs/ControlR.Agent/LogFile*.log'
            - '/Library/Application Support/ControlR/*/ControlR.Agent'
            - '/Applications/ControlR.app'
            - '/Applications/ControlR.*.app'
            - '/Library/LaunchDaemons/app.controlr.agent*.plist'
            - '/Library/LaunchAgents/app.controlr.desktop*.plist'
    condition: selection
falsepositives:
    - Legitimate use of ControlR
level: medium
```
