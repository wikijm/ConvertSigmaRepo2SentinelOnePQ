```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "/opt/dataplicity/tuxtunnel/manager" or tgt.file.path contains "/opt/dataplicity/credentials" or tgt.file.path contains "/etc/systemd/system/dataplicity.service" or tgt.file.path contains "/etc/init.d/dataplicity"))
```


# Original Sigma Rule:
```yaml
title: Potential Dataplicity RMM Tool File Activity
id: 984c9c4d-0bce-5c03-bdd3-d043a4c414bb
status: experimental
description: |
    Detects potential files activity of Dataplicity RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '/opt/dataplicity/tuxtunnel/manager'
            - '/opt/dataplicity/credentials'
            - '/etc/systemd/system/dataplicity.service'
            - '/etc/init.d/dataplicity'
    condition: selection
falsepositives:
    - Legitimate use of Dataplicity
level: medium
```
