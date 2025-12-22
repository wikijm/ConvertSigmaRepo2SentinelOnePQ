```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\Plugins\\Downloads\\Gorelo.RemoteManagement.AppManagement.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\Plugins\\Downloads\\Gorelo.RemoteManagement.DeviceChat.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\Plugins\\Downloads\\Gorelo.RemoteManagement.IpAddressDetector.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\Plugins\\Downloads\\Gorelo.RemoteManagement.ScreenCapture.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\Plugins\\Downloads\\Gorelo.RemoteManagement.ScriptRunner.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\Plugins\\Downloads\\Gorelo.RemoteManagement.ServerMonitor.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\Plugins\\Downloads\\Gorelo.RemoteManagement.ShellCommand.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\Plugins\\Downloads\\Gorelo.RemoteManagement.SystemProfiler.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\Plugins\\Downloads\\Gorelo.RemoteManagement.SystemSecurityManagement.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\Plugins\\Downloads\\Gorelo.RemoteManagement.WindowsChecker.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\Plugins\\Downloads\\Gorelo.RemoteManagement.WindowsPatchManagement.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\RMMAgent\\Gorelo.RemoteManagement.Agent\\Gorelo.RemoteManagement.Agent.exe" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Agent\\Shell\\Gorelo.RemoteManagement.Shell\\Gorelo.RemoteManagement.Shell.exe" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Installer\\Downloads\\Gorelo.RemoteManagement.Agent.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Installer\\Downloads\\Gorelo.RemoteManagement.Shell.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Installer\\Downloads\\Gorelo.Rmm.Installer.Handler.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Installer\\Downloads\\Gorelo.Rmm.Installer.zip" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Installer\\Gorelo.Rmm.Installer.Handler\\Gorelo.Rmm.Installer.Handler.exe" or tgt.file.path contains "C:\\Program Files\\Gorelo\\Installer\\Gorelo.Rmm.Installer\\Gorelo.Rmm.Installer.exe" or tgt.file.path="*C:\\Program Files\\Gorelo\\LogFiles\\Agent\\diagnostics-*.txt" or tgt.file.path="*C:\\Program Files\\Gorelo\\LogFiles\\Installer\\diagnostics-*.txt" or tgt.file.path="*C:\\Program Files\\Gorelo\\LogFiles\\InstallerHandler\\diagnostics-*.txt" or tgt.file.path="*C:\\Program Files\\Gorelo\\LogFiles\\Shell\\diagnostics-*.txt"))
```


# Original Sigma Rule:
```yaml
title: Potential Gorelo RMM RMM Tool File Activity
id: 301a3f86-aa1d-40d7-8f92-be35c7871b73
status: experimental
description: |
    Detects potential files activity of Gorelo RMM RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - C:\Program Files\Gorelo\Agent\Plugins\Downloads\Gorelo.RemoteManagement.AppManagement.zip
            - C:\Program Files\Gorelo\Agent\Plugins\Downloads\Gorelo.RemoteManagement.DeviceChat.zip
            - C:\Program Files\Gorelo\Agent\Plugins\Downloads\Gorelo.RemoteManagement.IpAddressDetector.zip
            - C:\Program Files\Gorelo\Agent\Plugins\Downloads\Gorelo.RemoteManagement.ScreenCapture.zip
            - C:\Program Files\Gorelo\Agent\Plugins\Downloads\Gorelo.RemoteManagement.ScriptRunner.zip
            - C:\Program Files\Gorelo\Agent\Plugins\Downloads\Gorelo.RemoteManagement.ServerMonitor.zip
            - C:\Program Files\Gorelo\Agent\Plugins\Downloads\Gorelo.RemoteManagement.ShellCommand.zip
            - C:\Program Files\Gorelo\Agent\Plugins\Downloads\Gorelo.RemoteManagement.SystemProfiler.zip
            - C:\Program Files\Gorelo\Agent\Plugins\Downloads\Gorelo.RemoteManagement.SystemSecurityManagement.zip
            - C:\Program Files\Gorelo\Agent\Plugins\Downloads\Gorelo.RemoteManagement.WindowsChecker.zip
            - C:\Program Files\Gorelo\Agent\Plugins\Downloads\Gorelo.RemoteManagement.WindowsPatchManagement.zip
            - C:\Program Files\Gorelo\Agent\RMMAgent\Gorelo.RemoteManagement.Agent\Gorelo.RemoteManagement.Agent.exe
            - C:\Program Files\Gorelo\Agent\Shell\Gorelo.RemoteManagement.Shell\Gorelo.RemoteManagement.Shell.exe
            - C:\Program Files\Gorelo\Installer\Downloads\Gorelo.RemoteManagement.Agent.zip
            - C:\Program Files\Gorelo\Installer\Downloads\Gorelo.RemoteManagement.Shell.zip
            - C:\Program Files\Gorelo\Installer\Downloads\Gorelo.Rmm.Installer.Handler.zip
            - C:\Program Files\Gorelo\Installer\Downloads\Gorelo.Rmm.Installer.zip
            - C:\Program Files\Gorelo\Installer\Gorelo.Rmm.Installer.Handler\Gorelo.Rmm.Installer.Handler.exe
            - C:\Program Files\Gorelo\Installer\Gorelo.Rmm.Installer\Gorelo.Rmm.Installer.exe
            - C:\Program Files\Gorelo\LogFiles\Agent\diagnostics-*.txt
            - C:\Program Files\Gorelo\LogFiles\Installer\diagnostics-*.txt
            - C:\Program Files\Gorelo\LogFiles\InstallerHandler\diagnostics-*.txt
            - C:\Program Files\Gorelo\LogFiles\Shell\diagnostics-*.txt
    condition: selection
falsepositives:
    - Legitimate use of Gorelo RMM
level: medium
```
