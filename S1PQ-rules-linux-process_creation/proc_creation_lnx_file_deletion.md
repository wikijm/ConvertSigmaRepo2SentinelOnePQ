```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/rm" or tgt.process.image.path contains "/shred" or tgt.process.image.path contains "/unlink"))
```


# Original Sigma Rule:
```yaml
title: File Deletion
id: 30aed7b6-d2c1-4eaf-9382-b6bc43e50c57
status: stable
description: Detects file deletion using "rm", "shred" or "unlink" commands which are used often by adversaries to delete files left behind by the actions of their intrusion activity
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.004/T1070.004.md
author: Ömer Günal, oscd.community
date: 2020-10-07
modified: 2022-09-15
tags:
    - attack.defense-evasion
    - attack.t1070.004
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/rm'     # covers /rmdir as well
            - '/shred'
            - '/unlink'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: informational
```
