```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "Add-Exfiltration" or tgt.process.cmdline contains "Add-Persistence" or tgt.process.cmdline contains "Add-RegBackdoor" or tgt.process.cmdline contains "Add-RemoteRegBackdoor" or tgt.process.cmdline contains "Add-ScrnSaveBackdoor" or tgt.process.cmdline contains "Check-VM" or tgt.process.cmdline contains "ConvertTo-Rc4ByteStream" or tgt.process.cmdline contains "Decrypt-Hash" or tgt.process.cmdline contains "Disable-ADIDNSNode" or tgt.process.cmdline contains "Disable-MachineAccount" or tgt.process.cmdline contains "Do-Exfiltration" or tgt.process.cmdline contains "Enable-ADIDNSNode" or tgt.process.cmdline contains "Enable-MachineAccount" or tgt.process.cmdline contains "Enabled-DuplicateToken" or tgt.process.cmdline contains "Exploit-Jboss" or tgt.process.cmdline contains "Export-ADR" or tgt.process.cmdline contains "Export-ADRCSV" or tgt.process.cmdline contains "Export-ADRExcel" or tgt.process.cmdline contains "Export-ADRHTML" or tgt.process.cmdline contains "Export-ADRJSON" or tgt.process.cmdline contains "Export-ADRXML" or tgt.process.cmdline contains "Find-Fruit" or tgt.process.cmdline contains "Find-GPOLocation" or tgt.process.cmdline contains "Find-TrustedDocuments" or tgt.process.cmdline contains "Get-ADIDNS" or tgt.process.cmdline contains "Get-ApplicationHost" or tgt.process.cmdline contains "Get-ChromeDump" or tgt.process.cmdline contains "Get-ClipboardContents" or tgt.process.cmdline contains "Get-FoxDump" or tgt.process.cmdline contains "Get-GPPPassword" or tgt.process.cmdline contains "Get-IndexedItem" or tgt.process.cmdline contains "Get-KerberosAESKey" or tgt.process.cmdline contains "Get-Keystrokes" or tgt.process.cmdline contains "Get-LSASecret" or tgt.process.cmdline contains "Get-MachineAccountAttribute" or tgt.process.cmdline contains "Get-MachineAccountCreator" or tgt.process.cmdline contains "Get-PassHashes" or tgt.process.cmdline contains "Get-RegAlwaysInstallElevated" or tgt.process.cmdline contains "Get-RegAutoLogon" or tgt.process.cmdline contains "Get-RemoteBootKey" or tgt.process.cmdline contains "Get-RemoteCachedCredential" or tgt.process.cmdline contains "Get-RemoteLocalAccountHash" or tgt.process.cmdline contains "Get-RemoteLSAKey" or tgt.process.cmdline contains "Get-RemoteMachineAccountHash" or tgt.process.cmdline contains "Get-RemoteNLKMKey" or tgt.process.cmdline contains "Get-RickAstley" or tgt.process.cmdline contains "Get-Screenshot" or tgt.process.cmdline contains "Get-SecurityPackages" or tgt.process.cmdline contains "Get-ServiceFilePermission" or tgt.process.cmdline contains "Get-ServicePermission" or tgt.process.cmdline contains "Get-ServiceUnquoted" or tgt.process.cmdline contains "Get-SiteListPassword" or tgt.process.cmdline contains "Get-System" or tgt.process.cmdline contains "Get-TimedScreenshot" or tgt.process.cmdline contains "Get-UnattendedInstallFile" or tgt.process.cmdline contains "Get-Unconstrained" or tgt.process.cmdline contains "Get-USBKeystrokes" or tgt.process.cmdline contains "Get-VaultCredential" or tgt.process.cmdline contains "Get-VulnAutoRun" or tgt.process.cmdline contains "Get-VulnSchTask" or tgt.process.cmdline contains "Grant-ADIDNSPermission" or tgt.process.cmdline contains "Gupt-Backdoor" or tgt.process.cmdline contains "HTTP-Login" or tgt.process.cmdline contains "Install-ServiceBinary" or tgt.process.cmdline contains "Install-SSP" or tgt.process.cmdline contains "Invoke-ACLScanner" or tgt.process.cmdline contains "Invoke-ADRecon" or tgt.process.cmdline contains "Invoke-ADSBackdoor" or tgt.process.cmdline contains "Invoke-AgentSmith" or tgt.process.cmdline contains "Invoke-AllChecks" or tgt.process.cmdline contains "Invoke-ARPScan" or tgt.process.cmdline contains "Invoke-AzureHound" or tgt.process.cmdline contains "Invoke-BackdoorLNK" or tgt.process.cmdline contains "Invoke-BadPotato" or tgt.process.cmdline contains "Invoke-BetterSafetyKatz" or tgt.process.cmdline contains "Invoke-BypassUAC" or tgt.process.cmdline contains "Invoke-Carbuncle" or tgt.process.cmdline contains "Invoke-Certify" or tgt.process.cmdline contains "Invoke-ConPtyShell" or tgt.process.cmdline contains "Invoke-CredentialInjection" or tgt.process.cmdline contains "Invoke-DAFT" or tgt.process.cmdline contains "Invoke-DCSync" or tgt.process.cmdline contains "Invoke-DinvokeKatz" or tgt.process.cmdline contains "Invoke-DllInjection" or tgt.process.cmdline contains "Invoke-DNSUpdate" or tgt.process.cmdline contains "Invoke-DNSExfiltrator" or tgt.process.cmdline contains "Invoke-DomainPasswordSpray" or tgt.process.cmdline contains "Invoke-DowngradeAccount" or tgt.process.cmdline contains "Invoke-EgressCheck" or tgt.process.cmdline contains "Invoke-Eyewitness" or tgt.process.cmdline contains "Invoke-FakeLogonScreen" or tgt.process.cmdline contains "Invoke-Farmer" or tgt.process.cmdline contains "Invoke-Get-RBCD-Threaded" or tgt.process.cmdline contains "Invoke-Gopher" or tgt.process.cmdline contains "Invoke-Grouper" or tgt.process.cmdline contains "Invoke-HandleKatz" or tgt.process.cmdline contains "Invoke-ImpersonatedProcess" or tgt.process.cmdline contains "Invoke-ImpersonateSystem" or tgt.process.cmdline contains "Invoke-InteractiveSystemPowerShell" or tgt.process.cmdline contains "Invoke-Internalmonologue" or tgt.process.cmdline contains "Invoke-Inveigh" or tgt.process.cmdline contains "Invoke-InveighRelay" or tgt.process.cmdline contains "Invoke-KrbRelay" or tgt.process.cmdline contains "Invoke-LdapSignCheck" or tgt.process.cmdline contains "Invoke-Lockless" or tgt.process.cmdline contains "Invoke-MalSCCM" or tgt.process.cmdline contains "Invoke-Mimikatz" or tgt.process.cmdline contains "Invoke-Mimikittenz" or tgt.process.cmdline contains "Invoke-MITM6" or tgt.process.cmdline contains "Invoke-NanoDump" or tgt.process.cmdline contains "Invoke-NetRipper" or tgt.process.cmdline contains "Invoke-Nightmare" or tgt.process.cmdline contains "Invoke-NinjaCopy" or tgt.process.cmdline contains "Invoke-OfficeScrape" or tgt.process.cmdline contains "Invoke-OxidResolver" or tgt.process.cmdline contains "Invoke-P0wnedshell" or tgt.process.cmdline contains "Invoke-Paranoia" or tgt.process.cmdline contains "Invoke-PortScan" or tgt.process.cmdline contains "Invoke-PoshRatHttp" or tgt.process.cmdline contains "Invoke-PostExfil" or tgt.process.cmdline contains "Invoke-PowerDump" or tgt.process.cmdline contains "Invoke-PowerDPAPI" or tgt.process.cmdline contains "Invoke-PowerShellTCP" or tgt.process.cmdline contains "Invoke-PowerShellWMI" or tgt.process.cmdline contains "Invoke-PPLDump" or tgt.process.cmdline contains "Invoke-PsExec" or tgt.process.cmdline contains "Invoke-PSInject" or tgt.process.cmdline contains "Invoke-PsUaCme" or tgt.process.cmdline contains "Invoke-ReflectivePEInjection" or tgt.process.cmdline contains "Invoke-ReverseDNSLookup" or tgt.process.cmdline contains "Invoke-Rubeus" or tgt.process.cmdline contains "Invoke-RunAs" or tgt.process.cmdline contains "Invoke-SafetyKatz" or tgt.process.cmdline contains "Invoke-SauronEye" or tgt.process.cmdline contains "Invoke-SCShell" or tgt.process.cmdline contains "Invoke-Seatbelt" or tgt.process.cmdline contains "Invoke-ServiceAbuse" or tgt.process.cmdline contains "Invoke-ShadowSpray" or tgt.process.cmdline contains "Invoke-Sharp" or tgt.process.cmdline contains "Invoke-Shellcode" or tgt.process.cmdline contains "Invoke-SMBScanner" or tgt.process.cmdline contains "Invoke-Snaffler" or tgt.process.cmdline contains "Invoke-Spoolsample" or tgt.process.cmdline contains "Invoke-SpraySinglePassword" or tgt.process.cmdline contains "Invoke-SSHCommand" or tgt.process.cmdline contains "Invoke-StandIn" or tgt.process.cmdline contains "Invoke-StickyNotesExtract" or tgt.process.cmdline contains "Invoke-SystemCommand" or tgt.process.cmdline contains "Invoke-Tasksbackdoor" or tgt.process.cmdline contains "Invoke-Tater" or tgt.process.cmdline contains "Invoke-Thunderfox" or tgt.process.cmdline contains "Invoke-ThunderStruck" or tgt.process.cmdline contains "Invoke-TokenManipulation" or tgt.process.cmdline contains "Invoke-Tokenvator" or tgt.process.cmdline contains "Invoke-TotalExec" or tgt.process.cmdline contains "Invoke-UrbanBishop" or tgt.process.cmdline contains "Invoke-UserHunter" or tgt.process.cmdline contains "Invoke-VoiceTroll" or tgt.process.cmdline contains "Invoke-Whisker" or tgt.process.cmdline contains "Invoke-WinEnum" or tgt.process.cmdline contains "Invoke-winPEAS" or tgt.process.cmdline contains "Invoke-WireTap" or tgt.process.cmdline contains "Invoke-WmiCommand" or tgt.process.cmdline contains "Invoke-WMIExec" or tgt.process.cmdline contains "Invoke-WScriptBypassUAC" or tgt.process.cmdline contains "Invoke-Zerologon" or tgt.process.cmdline contains "MailRaider" or tgt.process.cmdline contains "New-ADIDNSNode" or tgt.process.cmdline contains "New-DNSRecordArray" or tgt.process.cmdline contains "New-HoneyHash" or tgt.process.cmdline contains "New-InMemoryModule" or tgt.process.cmdline contains "New-MachineAccount" or tgt.process.cmdline contains "New-SOASerialNumberArray" or tgt.process.cmdline contains "Out-Minidump" or tgt.process.cmdline contains "Port-Scan" or tgt.process.cmdline contains "PowerBreach" or tgt.process.cmdline contains "powercat " or tgt.process.cmdline contains "PowerUp" or tgt.process.cmdline contains "PowerView" or tgt.process.cmdline contains "Remove-ADIDNSNode" or tgt.process.cmdline contains "Remove-MachineAccount" or tgt.process.cmdline contains "Remove-Update" or tgt.process.cmdline contains "Rename-ADIDNSNode" or tgt.process.cmdline contains "Revoke-ADIDNSPermission" or tgt.process.cmdline contains "Set-ADIDNSNode" or tgt.process.cmdline contains "Set-MacAttribute" or tgt.process.cmdline contains "Set-MachineAccountAttribute" or tgt.process.cmdline contains "Set-Wallpaper" or tgt.process.cmdline contains "Show-TargetScreen" or tgt.process.cmdline contains "Start-CaptureServer" or tgt.process.cmdline contains "Start-Dnscat2" or tgt.process.cmdline contains "Start-WebcamRecorder" or tgt.process.cmdline contains "Veeam-Get-Creds" or tgt.process.cmdline contains "VolumeShadowCopyTools"))
```


# Original Sigma Rule:
```yaml
title: Malicious PowerShell Commandlets - ProcessCreation
id: 02030f2f-6199-49ec-b258-ea71b07e03dc
related:
    - id: 89819aa4-bbd6-46bc-88ec-c7f7fe30efa6
      type: derived
    - id: 7d0d0329-0ef1-4e84-a9f5-49500f9d7c6c
      type: similar
status: test
description: Detects Commandlet names from well-known PowerShell exploitation frameworks
references:
    - https://adsecurity.org/?p=2921
    - https://github.com/S3cur3Th1sSh1t/PowerSharpPack/tree/master/PowerSharpBinaries
    - https://github.com/BC-SECURITY/Invoke-ZeroLogon/blob/111d17c7fec486d9bb23387e2e828b09a26075e4/Invoke-ZeroLogon.ps1
    - https://github.com/xorrior/RandomPS-Scripts/blob/848c919bfce4e2d67b626cbcf4404341cfe3d3b6/Get-DXWebcamVideo.ps1
    - https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/6f23bb41f9675d7e2d32bacccff75e931ae00554/OfficeMemScraper.ps1
    - https://github.com/dafthack/DomainPasswordSpray/blob/b13d64a5834694aa73fd2aea9911a83027c465a7/DomainPasswordSpray.ps1
    - https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware/ # Invoke-TotalExec
    - https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/ # Invoke-TotalExec
    - https://github.com/calebstewart/CVE-2021-1675 # Invoke-Nightmare
    - https://github.com/BloodHoundAD/BloodHound/blob/0927441f67161cc6dc08a53c63ceb8e333f55874/Collectors/AzureHound.ps1
    - https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html
    - https://github.com/HarmJ0y/DAMP
    - https://github.com/samratashok/nishang
    - https://github.com/DarkCoderSc/PowerRunAsSystem/
    - https://github.com/besimorhino/powercat
    - https://github.com/Kevin-Robertson/Powermad
    - https://github.com/adrecon/ADRecon
    - https://github.com/adrecon/AzureADRecon
    - https://github.com/sadshade/veeam-creds/blob/6010eaf31ba41011b58d6af3950cffbf6f5cea32/Veeam-Get-Creds.ps1
    - https://github.com/The-Viper-One/Invoke-PowerDPAPI/
    - https://github.com/Arno0x/DNSExfiltrator/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-02
modified: 2025-12-10
tags:
    - attack.execution
    - attack.discovery
    - attack.t1482
    - attack.t1087
    - attack.t1087.001
    - attack.t1087.002
    - attack.t1069.001
    - attack.t1069.002
    - attack.t1069
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Note: Please ensure alphabetical order when adding new entries
        CommandLine|contains:
            - 'Add-Exfiltration'
            - 'Add-Persistence'
            - 'Add-RegBackdoor'
            - 'Add-RemoteRegBackdoor'
            - 'Add-ScrnSaveBackdoor'
            - 'Check-VM'
            - 'ConvertTo-Rc4ByteStream'
            - 'Decrypt-Hash'
            - 'Disable-ADIDNSNode'
            - 'Disable-MachineAccount'
            - 'Do-Exfiltration'
            - 'Enable-ADIDNSNode'
            - 'Enable-MachineAccount'
            - 'Enabled-DuplicateToken'
            - 'Exploit-Jboss'
            - 'Export-ADR'
            - 'Export-ADRCSV'
            - 'Export-ADRExcel'
            - 'Export-ADRHTML'
            - 'Export-ADRJSON'
            - 'Export-ADRXML'
            - 'Find-Fruit'
            - 'Find-GPOLocation'
            - 'Find-TrustedDocuments'
            - 'Get-ADIDNS' # Covers: Get-ADIDNSNodeAttribute, Get-ADIDNSNodeOwner, Get-ADIDNSNodeTombstoned, Get-ADIDNSPermission, Get-ADIDNSZone
            - 'Get-ApplicationHost'
            - 'Get-ChromeDump'
            - 'Get-ClipboardContents'
            - 'Get-FoxDump'
            - 'Get-GPPPassword'
            - 'Get-IndexedItem'
            - 'Get-KerberosAESKey'
            - 'Get-Keystrokes'
            - 'Get-LSASecret'
            - 'Get-MachineAccountAttribute'
            - 'Get-MachineAccountCreator'
            - 'Get-PassHashes'
            - 'Get-RegAlwaysInstallElevated'
            - 'Get-RegAutoLogon'
            - 'Get-RemoteBootKey'
            - 'Get-RemoteCachedCredential'
            - 'Get-RemoteLocalAccountHash'
            - 'Get-RemoteLSAKey'
            - 'Get-RemoteMachineAccountHash'
            - 'Get-RemoteNLKMKey'
            - 'Get-RickAstley'
            - 'Get-Screenshot'
            - 'Get-SecurityPackages'
            - 'Get-ServiceFilePermission'
            - 'Get-ServicePermission'
            - 'Get-ServiceUnquoted'
            - 'Get-SiteListPassword'
            - 'Get-System'
            - 'Get-TimedScreenshot'
            - 'Get-UnattendedInstallFile'
            - 'Get-Unconstrained'
            - 'Get-USBKeystrokes'
            - 'Get-VaultCredential'
            - 'Get-VulnAutoRun'
            - 'Get-VulnSchTask'
            - 'Grant-ADIDNSPermission'
            - 'Gupt-Backdoor'
            - 'HTTP-Login'
            - 'Install-ServiceBinary'
            - 'Install-SSP'
            - 'Invoke-ACLScanner'
            - 'Invoke-ADRecon'
            - 'Invoke-ADSBackdoor'
            - 'Invoke-AgentSmith'
            - 'Invoke-AllChecks'
            - 'Invoke-ARPScan'
            - 'Invoke-AzureHound'
            - 'Invoke-BackdoorLNK'
            - 'Invoke-BadPotato'
            - 'Invoke-BetterSafetyKatz'
            - 'Invoke-BypassUAC'
            - 'Invoke-Carbuncle'
            - 'Invoke-Certify'
            - 'Invoke-ConPtyShell'
            - 'Invoke-CredentialInjection'
            - 'Invoke-DAFT'
            - 'Invoke-DCSync'
            - 'Invoke-DinvokeKatz'
            - 'Invoke-DllInjection'
            - 'Invoke-DNSUpdate'
            - 'Invoke-DNSExfiltrator'
            - 'Invoke-DomainPasswordSpray'
            - 'Invoke-DowngradeAccount'
            - 'Invoke-EgressCheck'
            - 'Invoke-Eyewitness'
            - 'Invoke-FakeLogonScreen'
            - 'Invoke-Farmer'
            - 'Invoke-Get-RBCD-Threaded'
            - 'Invoke-Gopher'
            - 'Invoke-Grouper' # Also Covers Invoke-GrouperX
            - 'Invoke-HandleKatz'
            - 'Invoke-ImpersonatedProcess'
            - 'Invoke-ImpersonateSystem'
            - 'Invoke-InteractiveSystemPowerShell'
            - 'Invoke-Internalmonologue'
            - 'Invoke-Inveigh'
            - 'Invoke-InveighRelay'
            - 'Invoke-KrbRelay'
            - 'Invoke-LdapSignCheck'
            - 'Invoke-Lockless'
            - 'Invoke-MalSCCM'
            - 'Invoke-Mimikatz'
            - 'Invoke-Mimikittenz'
            - 'Invoke-MITM6'
            - 'Invoke-NanoDump'
            - 'Invoke-NetRipper'
            - 'Invoke-Nightmare'
            - 'Invoke-NinjaCopy'
            - 'Invoke-OfficeScrape'
            - 'Invoke-OxidResolver'
            - 'Invoke-P0wnedshell'
            - 'Invoke-Paranoia'
            - 'Invoke-PortScan'
            - 'Invoke-PoshRatHttp' # Also Covers Invoke-PoshRatHttps
            - 'Invoke-PostExfil'
            - 'Invoke-PowerDump'
            - 'Invoke-PowerDPAPI'
            - 'Invoke-PowerShellTCP'
            - 'Invoke-PowerShellWMI'
            - 'Invoke-PPLDump'
            - 'Invoke-PsExec'
            - 'Invoke-PSInject'
            - 'Invoke-PsUaCme'
            - 'Invoke-ReflectivePEInjection'
            - 'Invoke-ReverseDNSLookup'
            - 'Invoke-Rubeus'
            - 'Invoke-RunAs'
            - 'Invoke-SafetyKatz'
            - 'Invoke-SauronEye'
            - 'Invoke-SCShell'
            - 'Invoke-Seatbelt'
            - 'Invoke-ServiceAbuse'
            - 'Invoke-ShadowSpray'
            - 'Invoke-Sharp' # Covers all "Invoke-Sharp" variants
            - 'Invoke-Shellcode'
            - 'Invoke-SMBScanner'
            - 'Invoke-Snaffler'
            - 'Invoke-Spoolsample'
            - 'Invoke-SpraySinglePassword'
            - 'Invoke-SSHCommand'
            - 'Invoke-StandIn'
            - 'Invoke-StickyNotesExtract'
            - 'Invoke-SystemCommand'
            - 'Invoke-Tasksbackdoor'
            - 'Invoke-Tater'
            - 'Invoke-Thunderfox'
            - 'Invoke-ThunderStruck'
            - 'Invoke-TokenManipulation'
            - 'Invoke-Tokenvator'
            - 'Invoke-TotalExec'
            - 'Invoke-UrbanBishop'
            - 'Invoke-UserHunter'
            - 'Invoke-VoiceTroll'
            - 'Invoke-Whisker'
            - 'Invoke-WinEnum'
            - 'Invoke-winPEAS'
            - 'Invoke-WireTap'
            - 'Invoke-WmiCommand'
            - 'Invoke-WMIExec'
            - 'Invoke-WScriptBypassUAC'
            - 'Invoke-Zerologon'
            - 'MailRaider'
            - 'New-ADIDNSNode'
            - 'New-DNSRecordArray'
            - 'New-HoneyHash'
            - 'New-InMemoryModule'
            - 'New-MachineAccount'
            - 'New-SOASerialNumberArray'
            - 'Out-Minidump'
            - 'Port-Scan'
            - 'PowerBreach'
            - 'powercat '
            - 'PowerUp'
            - 'PowerView'
            - 'Remove-ADIDNSNode'
            - 'Remove-MachineAccount'
            - 'Remove-Update'
            - 'Rename-ADIDNSNode'
            - 'Revoke-ADIDNSPermission'
            - 'Set-ADIDNSNode' # Covers: Set-ADIDNSNodeAttribute, Set-ADIDNSNodeOwner
            - 'Set-MacAttribute'
            - 'Set-MachineAccountAttribute'
            - 'Set-Wallpaper'
            - 'Show-TargetScreen'
            - 'Start-CaptureServer'
            - 'Start-Dnscat2'
            - 'Start-WebcamRecorder'
            - 'Veeam-Get-Creds'
            - 'VolumeShadowCopyTools'
    condition: selection
falsepositives:
    - Unknown
level: high
```
