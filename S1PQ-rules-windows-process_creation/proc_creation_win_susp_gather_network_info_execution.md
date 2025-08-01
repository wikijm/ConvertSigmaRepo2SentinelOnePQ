```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "gatherNetworkInfo.vbs" and (not (tgt.process.image.path contains "\cscript.exe" or tgt.process.image.path contains "\wscript.exe"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS
id: 07aa184a-870d-413d-893a-157f317f6f58
related:
    - id: f92a6f1e-a512-4a15-9735-da09e78d7273 # FileCreate
      type: similar
    - id: 575dce0c-8139-4e30-9295-1ee75969f7fe # ProcCreation LOLBIN
      type: similar
status: test
description: Detects execution of the built-in script located in "C:\Windows\System32\gatherNetworkInfo.vbs". Which can be used to gather information about the target machine
references:
    - https://posts.slayerlabs.com/living-off-the-land/#gathernetworkinfovbs
    - https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-08
tags:
    - attack.discovery
    - attack.execution
    - attack.t1615
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'gatherNetworkInfo.vbs'
    filter:
        Image|endswith:
            - '\cscript.exe'
            - '\wscript.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
