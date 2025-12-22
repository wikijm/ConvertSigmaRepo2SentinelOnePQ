```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\scrcons.exe" and (tgt.process.image.path contains "\\svchost.exe" or tgt.process.image.path contains "\\dllhost.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\msiexec.exe" or tgt.process.image.path contains "\\msbuild.exe")))
```


# Original Sigma Rule:
```yaml
title: Script Event Consumer Spawning Process
id: f6d1dd2f-b8ce-40ca-bc23-062efb686b34
status: test
description: Detects a suspicious child process of Script Event Consumer (scrcons.exe).
references:
    - https://redcanary.com/blog/child-processes/
    - https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-analytics-alert-reference/cortex-xdr-analytics-alert-reference/scrcons-exe-rare-child-process.html
author: Sittikorn S
date: 2021-06-21
modified: 2022-07-14
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\scrcons.exe'
        Image|endswith:
            - '\svchost.exe'
            - '\dllhost.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\schtasks.exe'
            - '\regsvr32.exe'
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\msiexec.exe'
            - '\msbuild.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
