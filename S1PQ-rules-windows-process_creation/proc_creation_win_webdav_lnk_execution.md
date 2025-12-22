```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\explorer.exe" and (tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\wscript.exe") and tgt.process.cmdline contains "\\DavWWWRoot\\"))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious WebDAV LNK Execution
id: 1412aa78-a24c-4abd-83df-767dfb2c5bbe
related:
    - id: f0507c0f-a3a2-40f5-acc6-7f543c334993
      type: similar
status: test
description: Detects possible execution via LNK file accessed on a WebDAV server.
references:
    - https://www.trellix.com/en-us/about/newsroom/stories/research/beyond-file-search-a-novel-method.html
    - https://micahbabinski.medium.com/search-ms-webdav-and-chill-99c5b23ac462
author: Micah Babinski
date: 2023-08-21
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1204
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\explorer.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
        CommandLine|contains: '\DavWWWRoot\'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
