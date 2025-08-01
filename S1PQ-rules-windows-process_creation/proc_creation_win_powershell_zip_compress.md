```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline="*Compress-Archive -Path*-DestinationPath $env:TEMP*" or tgt.process.cmdline="*Compress-Archive -Path*-DestinationPath*\AppData\Local\Temp\*" or tgt.process.cmdline="*Compress-Archive -Path*-DestinationPath*:\Windows\Temp\*"))
```


# Original Sigma Rule:
```yaml
title: Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet
id: 85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98 # Process Creation
related:
    - id: 71ff406e-b633-4989-96ec-bc49d825a412 # PowerShell Classic
      type: similar
    - id: daf7eb81-35fd-410d-9d7a-657837e602bb # PowerShell Module
      type: similar
    - id: b7a3c9a3-09ea-4934-8864-6a32cacd98d9 # PowerShell Script
      type: similar
status: test
description: |
    Detects PowerShell scripts that make use of the "Compress-Archive" Cmdlet in order to compress folders and files where the output is stored in a potentially suspicious location that is used often by malware for exfiltration.
    An adversary might compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1074.001/T1074.001.md
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
author: Nasreddine Bencherchali (Nextron Systems), frack113
date: 2021-07-20
modified: 2022-10-09
tags:
    - attack.collection
    - attack.t1074.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'Compress-Archive -Path*-DestinationPath $env:TEMP'
            - 'Compress-Archive -Path*-DestinationPath*\AppData\Local\Temp\'
            - 'Compress-Archive -Path*-DestinationPath*:\Windows\Temp\'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
