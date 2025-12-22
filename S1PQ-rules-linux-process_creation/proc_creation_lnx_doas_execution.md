```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and tgt.process.image.path contains "/doas")
```


# Original Sigma Rule:
```yaml
title: Linux Doas Tool Execution
id: 067d8238-7127-451c-a9ec-fa78045b618b
status: stable
description: Detects the doas tool execution in linux host platform. This utility tool allow standard users to perform tasks as root, the same way sudo does.
references:
    - https://research.splunk.com/endpoint/linux_doas_tool_execution/
    - https://www.makeuseof.com/how-to-install-and-use-doas/
author: Sittikorn S, Teoderick Contreras
date: 2022-01-20
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/doas'
    condition: selection
falsepositives:
    - Unlikely
level: low
```
