```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "Add-ADDBSidHistory" or tgt.process.cmdline contains "Add-ADNgcKey" or tgt.process.cmdline contains "Add-ADReplNgcKey" or tgt.process.cmdline contains "ConvertFrom-ADManagedPasswordBlob" or tgt.process.cmdline contains "ConvertFrom-GPPrefPassword" or tgt.process.cmdline contains "ConvertFrom-ManagedPasswordBlob" or tgt.process.cmdline contains "ConvertFrom-UnattendXmlPassword" or tgt.process.cmdline contains "ConvertFrom-UnicodePassword" or tgt.process.cmdline contains "ConvertTo-AADHash" or tgt.process.cmdline contains "ConvertTo-GPPrefPassword" or tgt.process.cmdline contains "ConvertTo-KerberosKey" or tgt.process.cmdline contains "ConvertTo-LMHash" or tgt.process.cmdline contains "ConvertTo-MsoPasswordHash" or tgt.process.cmdline contains "ConvertTo-NTHash" or tgt.process.cmdline contains "ConvertTo-OrgIdHash" or tgt.process.cmdline contains "ConvertTo-UnicodePassword" or tgt.process.cmdline contains "Disable-ADDBAccount" or tgt.process.cmdline contains "Enable-ADDBAccount" or tgt.process.cmdline contains "Get-ADDBAccount" or tgt.process.cmdline contains "Get-ADDBBackupKey" or tgt.process.cmdline contains "Get-ADDBDomainController" or tgt.process.cmdline contains "Get-ADDBGroupManagedServiceAccount" or tgt.process.cmdline contains "Get-ADDBKdsRootKey" or tgt.process.cmdline contains "Get-ADDBSchemaAttribute" or tgt.process.cmdline contains "Get-ADDBServiceAccount" or tgt.process.cmdline contains "Get-ADDefaultPasswordPolicy" or tgt.process.cmdline contains "Get-ADKeyCredential" or tgt.process.cmdline contains "Get-ADPasswordPolicy" or tgt.process.cmdline contains "Get-ADReplAccount" or tgt.process.cmdline contains "Get-ADReplBackupKey" or tgt.process.cmdline contains "Get-ADReplicationAccount" or tgt.process.cmdline contains "Get-ADSIAccount" or tgt.process.cmdline contains "Get-AzureADUserEx" or tgt.process.cmdline contains "Get-BootKey" or tgt.process.cmdline contains "Get-KeyCredential" or tgt.process.cmdline contains "Get-LsaBackupKey" or tgt.process.cmdline contains "Get-LsaPolicy" or tgt.process.cmdline contains "Get-SamPasswordPolicy" or tgt.process.cmdline contains "Get-SysKey" or tgt.process.cmdline contains "Get-SystemKey" or tgt.process.cmdline contains "New-ADDBRestoreFromMediaScript" or tgt.process.cmdline contains "New-ADKeyCredential" or tgt.process.cmdline contains "New-ADNgcKey" or tgt.process.cmdline contains "New-NTHashSet" or tgt.process.cmdline contains "Remove-ADDBObject" or tgt.process.cmdline contains "Save-DPAPIBlob" or tgt.process.cmdline contains "Set-ADAccountPasswordHash" or tgt.process.cmdline contains "Set-ADDBAccountPassword" or tgt.process.cmdline contains "Set-ADDBBootKey" or tgt.process.cmdline contains "Set-ADDBDomainController" or tgt.process.cmdline contains "Set-ADDBPrimaryGroup" or tgt.process.cmdline contains "Set-ADDBSysKey" or tgt.process.cmdline contains "Set-AzureADUserEx" or tgt.process.cmdline contains "Set-LsaPolicy" or tgt.process.cmdline contains "Set-SamAccountPasswordHash" or tgt.process.cmdline contains "Set-WinUserPasswordHash" or tgt.process.cmdline contains "Test-ADDBPasswordQuality" or tgt.process.cmdline contains "Test-ADPasswordQuality" or tgt.process.cmdline contains "Test-ADReplPasswordQuality" or tgt.process.cmdline contains "Test-PasswordQuality" or tgt.process.cmdline contains "Unlock-ADDBAccount" or tgt.process.cmdline contains "Write-ADNgcKey" or tgt.process.cmdline contains "Write-ADReplNgcKey"))
```


# Original Sigma Rule:
```yaml
title: DSInternals Suspicious PowerShell Cmdlets
id: 43d91656-a9b2-4541-b7e2-6a9bd3a13f4e
related:
    - id: 846c7a87-8e14-4569-9d49-ecfd4276a01c
      type: similar
status: test
description: |
    Detects execution and usage of the DSInternals PowerShell module. Which can be used to perform what might be considered as suspicious activity such as dumping DPAPI backup keys or manipulating NTDS.DIT files.
    The DSInternals PowerShell Module exposes several internal features of Active Directory and Azure Active Directory. These include FIDO2 and NGC key auditing, offline ntds.dit file manipulation, password auditing, DC recovery from IFM backups and password hash calculation.
references:
    - https://github.com/MichaelGrafnetter/DSInternals/blob/39ee8a69bbdc1cfd12c9afdd7513b4788c4895d4/Src/DSInternals.PowerShell/DSInternals.psd1
author: Nasreddine Bencherchali (Nextron Systems), Nounou Mbeiri
date: 2024-06-26
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'Add-ADDBSidHistory'
            - 'Add-ADNgcKey'
            - 'Add-ADReplNgcKey'
            - 'ConvertFrom-ADManagedPasswordBlob'
            - 'ConvertFrom-GPPrefPassword'
            - 'ConvertFrom-ManagedPasswordBlob'
            - 'ConvertFrom-UnattendXmlPassword'
            - 'ConvertFrom-UnicodePassword'
            - 'ConvertTo-AADHash'
            - 'ConvertTo-GPPrefPassword'
            - 'ConvertTo-KerberosKey'
            - 'ConvertTo-LMHash'
            - 'ConvertTo-MsoPasswordHash'
            - 'ConvertTo-NTHash'
            - 'ConvertTo-OrgIdHash'
            - 'ConvertTo-UnicodePassword'
            - 'Disable-ADDBAccount'
            - 'Enable-ADDBAccount'
            - 'Get-ADDBAccount'
            - 'Get-ADDBBackupKey'
            - 'Get-ADDBDomainController'
            - 'Get-ADDBGroupManagedServiceAccount'
            - 'Get-ADDBKdsRootKey'
            - 'Get-ADDBSchemaAttribute'
            - 'Get-ADDBServiceAccount'
            - 'Get-ADDefaultPasswordPolicy'
            - 'Get-ADKeyCredential' # Covers 'Get-ADKeyCredentialLink'
            - 'Get-ADPasswordPolicy'
            - 'Get-ADReplAccount'
            - 'Get-ADReplBackupKey'
            - 'Get-ADReplicationAccount'
            - 'Get-ADSIAccount'
            - 'Get-AzureADUserEx'
            - 'Get-BootKey'
            - 'Get-KeyCredential'
            - 'Get-LsaBackupKey'
            - 'Get-LsaPolicy' # Covers 'Get-LsaPolicyInformation'
            - 'Get-SamPasswordPolicy'
            - 'Get-SysKey'
            - 'Get-SystemKey'
            - 'New-ADDBRestoreFromMediaScript'
            - 'New-ADKeyCredential' # Covers 'New-ADKeyCredentialLink'
            - 'New-ADNgcKey'
            - 'New-NTHashSet'
            - 'Remove-ADDBObject'
            - 'Save-DPAPIBlob'
            - 'Set-ADAccountPasswordHash'
            - 'Set-ADDBAccountPassword' # Covers 'Set-ADDBAccountPasswordHash'
            - 'Set-ADDBBootKey'
            - 'Set-ADDBDomainController'
            - 'Set-ADDBPrimaryGroup'
            - 'Set-ADDBSysKey'
            - 'Set-AzureADUserEx'
            - 'Set-LsaPolicy' # Covers 'Set-LSAPolicyInformation'
            - 'Set-SamAccountPasswordHash'
            - 'Set-WinUserPasswordHash'
            - 'Test-ADDBPasswordQuality'
            - 'Test-ADPasswordQuality'
            - 'Test-ADReplPasswordQuality'
            - 'Test-PasswordQuality'
            - 'Unlock-ADDBAccount'
            - 'Write-ADNgcKey'
            - 'Write-ADReplNgcKey'
    condition: selection
falsepositives:
    - Legitimate usage of DSInternals for administration or audit purpose.
level: high
```
