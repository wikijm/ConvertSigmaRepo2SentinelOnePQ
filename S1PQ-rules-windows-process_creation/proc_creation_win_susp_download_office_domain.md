```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\curl.exe" or tgt.process.image.path contains "\wget.exe") or (tgt.process.cmdline contains "Invoke-WebRequest" or tgt.process.cmdline contains "iwr " or tgt.process.cmdline contains "curl " or tgt.process.cmdline contains "wget " or tgt.process.cmdline contains "Start-BitsTransfer" or tgt.process.cmdline contains ".DownloadFile(" or tgt.process.cmdline contains ".DownloadString(")) and (tgt.process.cmdline contains "https://attachment.outlook.live.net/owa/" or tgt.process.cmdline contains "https://onenoteonlinesync.onenote.com/onenoteonlinesync/")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Download from Office Domain
id: 00d49ed5-4491-4271-a8db-650a4ef6f8c1
status: test
description: Detects suspicious ways to download files from Microsoft domains that are used to store attachments in Emails or OneNote documents
references:
    - https://twitter.com/an0n_r0/status/1474698356635193346?s=12
    - https://twitter.com/mrd0x/status/1475085452784844803?s=12
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2021-12-27
modified: 2022-08-02
tags:
    - attack.command-and-control
    - attack.resource-development
    - attack.t1105
    - attack.t1608
logsource:
    product: windows
    category: process_creation
detection:
    selection_download:
        - Image|endswith:
              - '\curl.exe'
              - '\wget.exe'
        - CommandLine|contains:
              - 'Invoke-WebRequest'
              - 'iwr '
              - 'curl '
              - 'wget '
              - 'Start-BitsTransfer'
              - '.DownloadFile('
              - '.DownloadString('
    selection_domains:
        CommandLine|contains:
            - 'https://attachment.outlook.live.net/owa/'
            - 'https://onenoteonlinesync.onenote.com/onenoteonlinesync/'
    condition: all of selection_*
falsepositives:
    - Scripts or tools that download attachments from these domains (OneNote, Outlook 365)
level: high
```
