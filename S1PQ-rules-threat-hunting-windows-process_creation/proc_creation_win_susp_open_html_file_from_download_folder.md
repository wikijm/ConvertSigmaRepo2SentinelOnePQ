```sql
// Translated content (automatically translated on 22-12-2025 00:55:34):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\brave.exe" or tgt.process.image.path contains "\\chrome.exe" or tgt.process.image.path contains "\\firefox.exe" or tgt.process.image.path contains "\\msedge.exe" or tgt.process.image.path contains "\\opera.exe" or tgt.process.image.path contains "\\vivaldi.exe") and (tgt.process.cmdline contains ":\\users\\" and tgt.process.cmdline contains "\\Downloads\\" and tgt.process.cmdline contains ".htm")))
```


# Original Sigma Rule:
```yaml
title: HTML File Opened From Download Folder
id: 538c5851-8c03-4724-8ec4-623bc7aadaea
status: experimental
description: |
    Detects web browser process opening an HTML file from a user's Downloads folder.
    This behavior is could be associated with phishing attacks where threat actors send HTML attachments to users.
    When a user opens such an attachment, it can lead to the execution of malicious scripts or the download of malware.
    During investigation, analyze the HTML file for embedded scripts or links, check for any subsequent downloads or process executions, and investigate the source of the email or message containing the attachment.
references:
    - https://app.any.run/tasks/ae3c4ded-fd6a-43ed-8215-ba0ba574ad33
    - https://app.any.run/tasks/8901e2d5-0c5a-48ba-a8e9-10b5ed7e06f4
author: Joseph Kamau
date: 2025-12-05
tags:
    - attack.t1598.002
    - attack.t1566.001
    - attack.initial-access
    - attack.reconnaissance
    - detection.threat-hunting
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\vivaldi.exe'
        CommandLine|contains|all:
            - ':\users\'
            - '\Downloads\'
            - '.htm'
    condition: selection
falsepositives:
    - Opening any HTML file located in users directories via a browser process will trigger this.
level: low
```
