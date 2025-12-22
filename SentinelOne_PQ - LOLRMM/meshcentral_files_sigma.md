```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\Mesh Agent\\MeshAgent.exe" or tgt.file.path contains "C:\\Program Files\\Mesh Agent\\MeshAgent.msh" or tgt.file.path contains "/usr/local/mesh_services/meshagent/meshagent/meshagent" or tgt.file.path contains "/usr/local/mesh_services/meshagent/meshagent/meshagent.db" or tgt.file.path contains "/usr/local/mesh_services/meshagent/meshagent/meshagent.msh" or tgt.file.path contains "/usr/local/mesh_services/meshagent/meshagent" or tgt.file.path contains "/usr/local/mesh_services/meshagent/meshagent.db" or tgt.file.path contains "/usr/local/mesh_services/meshagent/meshagent.msh"))
```


# Original Sigma Rule:
```yaml
title: Potential MeshCentral RMM Tool File Activity
id: 1bb123a1-a6df-4f6f-88ac-35881e1ba861
status: experimental
description: |
    Detects potential files activity of MeshCentral RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - C:\Program Files\Mesh Agent\MeshAgent.exe
            - C:\Program Files\Mesh Agent\MeshAgent.msh
            - /usr/local/mesh_services/meshagent/meshagent/meshagent
            - /usr/local/mesh_services/meshagent/meshagent/meshagent.db
            - /usr/local/mesh_services/meshagent/meshagent/meshagent.msh
            - /usr/local/mesh_services/meshagent/meshagent
            - /usr/local/mesh_services/meshagent/meshagent.db
            - /usr/local/mesh_services/meshagent/meshagent.msh
    condition: selection
falsepositives:
    - Legitimate use of MeshCentral
level: medium
```
