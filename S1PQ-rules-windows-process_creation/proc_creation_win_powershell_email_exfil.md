```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe") and (tgt.process.cmdline contains "Add-PSSnapin" and tgt.process.cmdline contains "Get-Recipient" and tgt.process.cmdline contains "-ExpandProperty" and tgt.process.cmdline contains "EmailAddresses" and tgt.process.cmdline contains "SmtpAddress" and tgt.process.cmdline contains "-hidetableheaders")))
```


# Original Sigma Rule:
```yaml
title: Email Exifiltration Via Powershell
id: 312d0384-401c-4b8b-abdf-685ffba9a332
status: test
description: Detects email exfiltration via powershell cmdlets
references:
    - https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
    - https://github.com/Azure/Azure-Sentinel/blob/7e6aa438e254d468feec061618a7877aa528ee9f/Hunting%20Queries/Microsoft%20365%20Defender/Ransomware/DEV-0270/Email%20data%20exfiltration%20via%20PowerShell.yaml
author: Nasreddine Bencherchali (Nextron Systems),  Azure-Sentinel (idea)
date: 2022-09-09
tags:
    - attack.exfiltration
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'Add-PSSnapin'
            - 'Get-Recipient'
            - '-ExpandProperty'
            - 'EmailAddresses'
            - 'SmtpAddress'
            - '-hidetableheaders'
    condition: selection
falsepositives:
    - Unknown
level: high
```
