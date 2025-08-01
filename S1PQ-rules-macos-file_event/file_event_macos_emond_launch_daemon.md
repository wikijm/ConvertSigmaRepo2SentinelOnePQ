```sql
// Translated content (automatically translated on 02-08-2025 01:37:53):
event.category="file" and (endpoint.os="osx" and ((tgt.file.path contains "/etc/emond.d/rules/" and tgt.file.path contains ".plist") or tgt.file.path contains "/private/var/db/emondClients/"))
```


# Original Sigma Rule:
```yaml
title: MacOS Emond Launch Daemon
id: 23c43900-e732-45a4-8354-63e4a6c187ce
status: test
description: Detects additions to the Emond Launch Daemon that adversaries may use to gain persistence and elevate privileges.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.014/T1546.014.md
    - https://posts.specterops.io/leveraging-emond-on-macos-for-persistence-a040a2785124
author: Alejandro Ortuno, oscd.community
date: 2020-10-23
modified: 2021-11-27
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1546.014
logsource:
    category: file_event
    product: macos
detection:
    selection_1:
        TargetFilename|contains: '/etc/emond.d/rules/'
        TargetFilename|endswith: '.plist'
    selection_2:
        TargetFilename|contains: '/private/var/db/emondClients/'
    condition: 1 of selection_*
falsepositives:
    - Legitimate administration activities
level: medium
```
