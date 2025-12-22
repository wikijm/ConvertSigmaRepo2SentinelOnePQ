```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\vsls-agent.exe" and tgt.process.cmdline contains "--agentExtensionPath") and (not tgt.process.cmdline contains "Microsoft.VisualStudio.LiveShare.Agent.")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Vsls-Agent Command With AgentExtensionPath Load
id: 43103702-5886-11ed-9b6a-0242ac120002
status: test
description: Detects Microsoft Visual Studio vsls-agent.exe lolbin execution with a suspicious library load using the --agentExtensionPath parameter
references:
    - https://twitter.com/bohops/status/1583916360404729857
author: bohops
date: 2022-10-30
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\vsls-agent.exe'
        CommandLine|contains: '--agentExtensionPath'
    filter:
        CommandLine|contains: 'Microsoft.VisualStudio.LiveShare.Agent.'
    condition: selection and not filter
falsepositives:
    - False positives depend on custom use of vsls-agent.exe
level: medium
```
