```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\" and tgt.process.image.path contains "\DavWWWRoot\"))
```


# Original Sigma Rule:
```yaml
title: Process Execution From WebDAV Share
id: f8de9dd5-7a63-4cfd-9d0c-ae124878b5a9
status: experimental
description: |
    Detects execution of processes with image paths starting with WebDAV shares (\\), which might indicate malicious file execution from remote web shares.
    Execution of processes from WebDAV shares can be a sign of lateral movement or exploitation attempts, especially if the process is not a known legitimate application.
    Exploitation Attempt of vulnerabilities like CVE-2025-33053 also involves executing processes from WebDAV paths.
references:
    - https://research.checkpoint.com/2025/stealth-falcon-zero-day/
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-06-13
tags:
    - attack.execution
    - attack.lateral-movement
    - attack.t1105
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|startswith: '\\\\'
        Image|contains: '\DavWWWRoot\'
    condition: selection
falsepositives:
    - Legitimate use of WebDAV shares for process execution
    - Known applications executing from WebDAV paths
level: low
```
