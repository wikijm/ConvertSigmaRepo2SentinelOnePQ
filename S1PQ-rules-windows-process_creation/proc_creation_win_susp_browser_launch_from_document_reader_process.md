```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "Acrobat Reader" or src.process.image.path contains "Microsoft Office" or src.process.image.path contains "PDF Reader") and (tgt.process.image.path contains "\\brave.exe" or tgt.process.image.path contains "\\chrome.exe" or tgt.process.image.path contains "\\firefox.exe" or tgt.process.image.path contains "\\msedge.exe" or tgt.process.image.path contains "\\opera.exe" or tgt.process.image.path contains "\\maxthon.exe" or tgt.process.image.path contains "\\seamonkey.exe" or tgt.process.image.path contains "\\vivaldi.exe") and tgt.process.cmdline contains "http") and (not tgt.process.cmdline contains "https://go.microsoft.com/fwlink/") and (not (tgt.process.cmdline="*http://ad.foxitsoftware.com/adlog.php**" or tgt.process.cmdline="*https://globe-map.foxitservice.com/go.php*do=redirect*"))))
```


# Original Sigma Rule:
```yaml
title: Potential Suspicious Browser Launch From Document Reader Process
id: 1193d960-2369-499f-a158-7b50a31df682
status: test
description: |
    Detects when a browser process or browser tab is launched from an application that handles document files such as Adobe, Microsoft Office, etc. And connects to a web application over http(s), this could indicate a possible phishing attempt.
references:
    - https://app.any.run/tasks/69c5abaa-92ad-45ba-8c53-c11e23e05d04/ # PDF Document
    - https://app.any.run/tasks/64043a79-165f-4052-bcba-e6e49f847ec1/ # Office Document
author: Joseph Kamau
date: 2024-05-27
modified: 2025-10-07
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|contains:
            - 'Acrobat Reader'
            - 'Microsoft Office'
            - 'PDF Reader'
        Image|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\maxthon.exe'
            - '\seamonkey.exe'
            - '\vivaldi.exe'
        CommandLine|contains: 'http'
    filter_main_microsoft_help:
        CommandLine|contains: 'https://go.microsoft.com/fwlink/'
    filter_optional_foxit:
        CommandLine|contains:
            - 'http://ad.foxitsoftware.com/adlog.php?'
            - 'https://globe-map.foxitservice.com/go.php?do=redirect'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unlikely in most cases, further investigation should be done in the commandline of the browser process to determine the context of the URL accessed.
level: medium
```
