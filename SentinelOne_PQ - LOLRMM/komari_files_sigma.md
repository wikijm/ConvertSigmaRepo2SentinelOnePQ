```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\Komari\\komari-agent.exe" or tgt.file.path contains "C:\\Program Files\\Komari\\nssm.exe" or tgt.file.path contains "C:\\komari\\agent" or tgt.file.path contains "/opt/komari/komari" or tgt.file.path contains "/opt/komari/agent" or tgt.file.path contains "/usr/local/komari/agent" or tgt.file.path contains "/etc/systemd/system/komari.service" or tgt.file.path contains "/etc/systemd/system/komari-agent.service"))
```


# Original Sigma Rule:
```yaml
title: Potential Komari RMM Tool File Activity
id: ca645bb0-5fd1-5ed0-ab3b-237adbf04948
status: experimental
description: |
    Detects potential files activity of Komari RMM tool
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
            - 'C:\Program Files\Komari\komari-agent.exe'
            - 'C:\Program Files\Komari\nssm.exe'
            - 'C:\komari\agent'
            - '/opt/komari/komari'
            - '/opt/komari/agent'
            - '/usr/local/komari/agent'
            - '/etc/systemd/system/komari.service'
            - '/etc/systemd/system/komari-agent.service'
    condition: selection
falsepositives:
    - Legitimate use of Komari
level: medium
```
