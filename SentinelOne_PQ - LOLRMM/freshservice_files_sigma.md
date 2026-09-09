```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\Freshdesk\\Freshservice Discovery Agent\\FSAgentService.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshdesk\\Freshservice Discovery Agent\\FSAgentAutoUpdate.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshdesk\\Freshservice Discovery Agent\\FSAgentCrashStatusUpdater.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshdesk\\Freshservice Discovery Agent\\FSWmiScanner.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshdesk\\Freshservice Discovery Agent\\AgentInstaller.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshdesk\\Freshservice Discovery Agent\\FSUtil.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshdesk\\Freshservice Discovery Agent\\Newtonsoft.Json.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshdesk\\Freshservice Discovery Agent\\log4net.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshdesk\\Freshservice Discovery Agent\\Microsoft.Win32.TaskScheduler.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshdesk\\Freshservice Discovery Agent\\settings.conf" or tgt.file.path contains "C:\\Program Files (x86)\\Freshdesk\\Freshservice Discovery Agent\\fslogger.xml" or tgt.file.path contains "C:\\Program Files (x86)\\Freshdesk\\Freshservice Discovery Agent\\logs\*" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.DiscoveryProbe.ScanService.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.DiscoveryProbe.Window.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\AutoUpdate.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.DiscoveryProbe.AutoFlush.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.DiscoveryProbe.OIDLibraryPuller.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.DiscoveryProbe.ProgressBar.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\FSProbeReporter.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\FSProbeCrashStatusUpdater.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\UninstallStatusUpdater.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\FSScheduler.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\FSWmiScanner.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\IPRangeCalculator.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\plink.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.DiscoveryProbe.ScanService.exe.config" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.DiscoveryProbe.Model.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.DiscoveryProbe.PostMan.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.DiscoveryProbe.GlobalSettings.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.DiscoveryProbe.Linux.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.DiscoveryProbe.Scanner.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.DiscoveryProbe.UtilitiesWrapper.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.Discovery.SNMP.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.Discovery.Utilities.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Freshservice.Integrations.SCCM.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Vim25Service.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Renci.SshNet.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\SnmpSharpNet.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\System.Data.SQLite.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\SQLite.Interop.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\bin\\Microsoft.Win32.TaskScheduler.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\db\\freshservice_discovery.db" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\conf\\Configurations.json" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\conf\\fslogger.xml" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\conf\\fsautoupdatelogger.xml" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\nmap\\nmap-service-probes" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\scan\\windows_scripts\\ListADComputers.vbs" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\scan\\windows_scripts\\ListDomains.vbs" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\scan\\windows_scripts\\GetComputerInfo.vbs" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\scan\\unix_scripts\\unix_ssh_scan.sh" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\Uninstall.bat" or tgt.file.path contains "C:\\Program Files (x86)\\Freshworks\\FreshServiceProbe\\MsiUpdater.vbs" or tgt.file.path contains "FSProbeUninstall.vbs" or tgt.file.path contains "%PROGRAMFILES(X86)%\\Freshdesk\\Freshservice Discovery Agent\*" or tgt.file.path contains "%PROGRAMFILES(X86)%\\Freshworks\\FreshServiceProbe\*" or tgt.file.path contains "/Applications/Freshservice Discovery Agent.app" or tgt.file.path contains "/opt/freshservice/discovery_agent/"))
```


# Original Sigma Rule:
```yaml
title: Potential Freshservice RMM Tool File Activity
id: c772a0f5-050e-5f57-9709-2c0c735215a9
status: experimental
description: |
    Detects potential files activity of Freshservice RMM tool
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
            - 'C:\Program Files (x86)\Freshdesk\Freshservice Discovery Agent\FSAgentService.exe'
            - 'C:\Program Files (x86)\Freshdesk\Freshservice Discovery Agent\FSAgentAutoUpdate.exe'
            - 'C:\Program Files (x86)\Freshdesk\Freshservice Discovery Agent\FSAgentCrashStatusUpdater.exe'
            - 'C:\Program Files (x86)\Freshdesk\Freshservice Discovery Agent\FSWmiScanner.exe'
            - 'C:\Program Files (x86)\Freshdesk\Freshservice Discovery Agent\AgentInstaller.dll'
            - 'C:\Program Files (x86)\Freshdesk\Freshservice Discovery Agent\FSUtil.dll'
            - 'C:\Program Files (x86)\Freshdesk\Freshservice Discovery Agent\Newtonsoft.Json.dll'
            - 'C:\Program Files (x86)\Freshdesk\Freshservice Discovery Agent\log4net.dll'
            - 'C:\Program Files (x86)\Freshdesk\Freshservice Discovery Agent\Microsoft.Win32.TaskScheduler.dll'
            - 'C:\Program Files (x86)\Freshdesk\Freshservice Discovery Agent\settings.conf'
            - 'C:\Program Files (x86)\Freshdesk\Freshservice Discovery Agent\fslogger.xml'
            - 'C:\Program Files (x86)\Freshdesk\Freshservice Discovery Agent\logs\*'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.DiscoveryProbe.ScanService.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.DiscoveryProbe.Window.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\AutoUpdate.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.DiscoveryProbe.AutoFlush.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.DiscoveryProbe.OIDLibraryPuller.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.DiscoveryProbe.ProgressBar.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\FSProbeReporter.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\FSProbeCrashStatusUpdater.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\UninstallStatusUpdater.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\FSScheduler.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\FSWmiScanner.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\IPRangeCalculator.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\plink.exe'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.DiscoveryProbe.ScanService.exe.config'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.DiscoveryProbe.Model.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.DiscoveryProbe.PostMan.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.DiscoveryProbe.GlobalSettings.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.DiscoveryProbe.Linux.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.DiscoveryProbe.Scanner.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.DiscoveryProbe.UtilitiesWrapper.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.Discovery.SNMP.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.Discovery.Utilities.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Freshservice.Integrations.SCCM.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Vim25Service.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Renci.SshNet.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\SnmpSharpNet.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\System.Data.SQLite.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\SQLite.Interop.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\bin\Microsoft.Win32.TaskScheduler.dll'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\db\freshservice_discovery.db'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\conf\Configurations.json'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\conf\fslogger.xml'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\conf\fsautoupdatelogger.xml'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\nmap\nmap-service-probes'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\scan\windows_scripts\ListADComputers.vbs'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\scan\windows_scripts\ListDomains.vbs'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\scan\windows_scripts\GetComputerInfo.vbs'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\scan\unix_scripts\unix_ssh_scan.sh'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\Uninstall.bat'
            - 'C:\Program Files (x86)\Freshworks\FreshServiceProbe\MsiUpdater.vbs'
            - 'FSProbeUninstall.vbs'
            - '%PROGRAMFILES(X86)%\Freshdesk\Freshservice Discovery Agent\*'
            - '%PROGRAMFILES(X86)%\Freshworks\FreshServiceProbe\*'
            - '/Applications/Freshservice Discovery Agent.app'
            - '/opt/freshservice/discovery_agent/*'
    condition: selection
falsepositives:
    - Legitimate use of Freshservice
level: medium
```
