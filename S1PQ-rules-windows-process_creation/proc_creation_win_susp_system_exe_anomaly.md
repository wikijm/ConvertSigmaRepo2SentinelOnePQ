```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\atbroker.exe" or tgt.process.image.path contains "\\audiodg.exe" or tgt.process.image.path contains "\\bcdedit.exe" or tgt.process.image.path contains "\\bitsadmin.exe" or tgt.process.image.path contains "\\certreq.exe" or tgt.process.image.path contains "\\certutil.exe" or tgt.process.image.path contains "\\cmstp.exe" or tgt.process.image.path contains "\\conhost.exe" or tgt.process.image.path contains "\\consent.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\csrss.exe" or tgt.process.image.path contains "\\dashost.exe" or tgt.process.image.path contains "\\defrag.exe" or tgt.process.image.path contains "\\dfrgui.exe" or tgt.process.image.path contains "\\dism.exe" or tgt.process.image.path contains "\\dllhost.exe" or tgt.process.image.path contains "\\dllhst3g.exe" or tgt.process.image.path contains "\\dwm.exe" or tgt.process.image.path contains "\\eventvwr.exe" or tgt.process.image.path contains "\\logonui.exe" or tgt.process.image.path contains "\\LsaIso.exe" or tgt.process.image.path contains "\\lsass.exe" or tgt.process.image.path contains "\\lsm.exe" or tgt.process.image.path contains "\\msiexec.exe" or tgt.process.image.path contains "\\ntoskrnl.exe" or tgt.process.image.path contains "\\powershell_ise.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\runonce.exe" or tgt.process.image.path contains "\\RuntimeBroker.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\services.exe" or tgt.process.image.path contains "\\sihost.exe" or tgt.process.image.path contains "\\smartscreen.exe" or tgt.process.image.path contains "\\smss.exe" or tgt.process.image.path contains "\\spoolsv.exe" or tgt.process.image.path contains "\\svchost.exe" or tgt.process.image.path contains "\\taskhost.exe" or tgt.process.image.path contains "\\taskhostw.exe" or tgt.process.image.path contains "\\Taskmgr.exe" or tgt.process.image.path contains "\\userinit.exe" or tgt.process.image.path contains "\\werfault.exe" or tgt.process.image.path contains "\\werfaultsecure.exe" or tgt.process.image.path contains "\\wininit.exe" or tgt.process.image.path contains "\\winlogon.exe" or tgt.process.image.path contains "\\winver.exe" or tgt.process.image.path contains "\\wlanext.exe" or tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\wsl.exe" or tgt.process.image.path contains "\\wsmprovhost.exe") and (not ((tgt.process.image.path contains "C:\\$WINDOWS.~BT\\" or tgt.process.image.path contains "C:\\$WinREAgent\\" or tgt.process.image.path contains "C:\\Windows\\SoftwareDistribution\\" or tgt.process.image.path contains "C:\\Windows\\System32\\" or tgt.process.image.path contains "C:\\Windows\\SystemTemp\\" or tgt.process.image.path contains "C:\\Windows\\SysWOW64\\" or tgt.process.image.path contains "C:\\Windows\\uus\\" or tgt.process.image.path contains "C:\\Windows\\WinSxS\\") or ((tgt.process.image.path contains "C:\\Program Files\\PowerShell\\7\\" or tgt.process.image.path contains "C:\\Program Files\\PowerShell\\7-preview\\" or tgt.process.image.path contains "C:\\Program Files\\WindowsApps\\Microsoft.PowerShellPreview" or tgt.process.image.path contains "\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.PowerShellPreview") and tgt.process.image.path contains "\\pwsh.exe") or ((tgt.process.image.path contains "C:\\Program Files\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux" or tgt.process.image.path contains "C:\\Program Files\\WSL\\") and tgt.process.image.path contains "\\wsl.exe") or (tgt.process.image.path contains "C:\\Users\\'" and tgt.process.image.path contains "\\AppData\\Local\\Microsoft\\WindowsApps\\" and tgt.process.image.path contains "\\wsl.exe"))) and (not tgt.process.image.path contains "\\SystemRoot\\System32\\")))
```


# Original Sigma Rule:
```yaml
title: System File Execution Location Anomaly
id: e4a6b256-3e47-40fc-89d2-7a477edd6915
related:
    - id: be58d2e2-06c8-4f58-b666-b99f6dc3b6cd # Dedicated SvcHost rule
      type: derived
status: test
description: |
    Detects the execution of a Windows system binary that is usually located in the system folder from an uncommon location.
references:
    - https://twitter.com/GelosSnake/status/934900723426439170
    - https://asec.ahnlab.com/en/39828/
    - https://www.splunk.com/en_us/blog/security/inno-setup-malware-redline-stealer-campaign.html
author: Florian Roth (Nextron Systems), Patrick Bareiss, Anton Kutepov, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2017-11-27
modified: 2025-11-23
tags:
    - attack.defense-evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\atbroker.exe'
            - '\audiodg.exe'
            - '\bcdedit.exe'
            - '\bitsadmin.exe'
            - '\certreq.exe'
            - '\certutil.exe'
            - '\cmstp.exe'
            - '\conhost.exe'
            - '\consent.exe'
            - '\cscript.exe'
            - '\csrss.exe'
            - '\dashost.exe'
            - '\defrag.exe'
            - '\dfrgui.exe' # Was seen used by Lazarus Group - https://asec.ahnlab.com/en/39828/
            - '\dism.exe'
            - '\dllhost.exe'
            - '\dllhst3g.exe'
            - '\dwm.exe'
            - '\eventvwr.exe'
            - '\logonui.exe'
            - '\LsaIso.exe'
            - '\lsass.exe'
            - '\lsm.exe'
            - '\msiexec.exe'
            - '\ntoskrnl.exe'
            - '\powershell_ise.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\runonce.exe'
            - '\RuntimeBroker.exe'
            - '\schtasks.exe'
            - '\services.exe'
            - '\sihost.exe'
            - '\smartscreen.exe'
            - '\smss.exe'
            - '\spoolsv.exe'
            - '\svchost.exe'
            - '\taskhost.exe'
            - '\taskhostw.exe'
            - '\Taskmgr.exe'
            - '\userinit.exe'
            - '\werfault.exe'
            - '\werfaultsecure.exe'
            - '\wininit.exe'
            - '\winlogon.exe'
            - '\winver.exe'
            - '\wlanext.exe'
            - '\wscript.exe'
            - '\wsl.exe'
            - '\wsmprovhost.exe' # Was seen used by Lazarus Group - https://asec.ahnlab.com/en/39828/
    filter_main_generic:
        Image|startswith:
            - 'C:\$WINDOWS.~BT\'
            - 'C:\$WinREAgent\'
            - 'C:\Windows\SoftwareDistribution\'
            - 'C:\Windows\System32\'
            - 'C:\Windows\SystemTemp\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\uus\'
            - 'C:\Windows\WinSxS\'
    filter_optional_system32:
        Image|contains: '\SystemRoot\System32\'
    filter_main_powershell:
        Image|contains:
            - 'C:\Program Files\PowerShell\7\'
            - 'C:\Program Files\PowerShell\7-preview\'
            - 'C:\Program Files\WindowsApps\Microsoft.PowerShellPreview'
            - '\AppData\Local\Microsoft\WindowsApps\Microsoft.PowerShellPreview' # pwsh installed from Microsoft Store
        Image|endswith: '\pwsh.exe'
    filter_main_wsl_programfiles:
        Image|startswith:
            - 'C:\Program Files\WindowsApps\MicrosoftCorporationII.WindowsSubsystemForLinux'
            - 'C:\Program Files\WSL\'
        Image|endswith: '\wsl.exe'
    filter_main_wsl_appdata:
        Image|startswith: C:\Users\'
        Image|contains: '\AppData\Local\Microsoft\WindowsApps\'
        Image|endswith: '\wsl.exe'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: high
```
