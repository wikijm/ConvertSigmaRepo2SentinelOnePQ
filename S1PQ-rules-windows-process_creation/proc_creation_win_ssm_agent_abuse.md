```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\amazon-ssm-agent.exe" and (tgt.process.cmdline contains "-register " and tgt.process.cmdline contains "-code " and tgt.process.cmdline contains "-id " and tgt.process.cmdline contains "-region ")))
```


# Original Sigma Rule:
```yaml
title: Potential Amazon SSM Agent Hijacking
id: d20ee2f4-822c-4827-9e15-41500b1fff10
status: test
description: Detects potential Amazon SSM agent hijack attempts as outlined in the Mitiga research report.
references:
    - https://www.mitiga.io/blog/mitiga-security-advisory-abusing-the-ssm-agent-as-a-remote-access-trojan
    - https://www.bleepingcomputer.com/news/security/amazons-aws-ssm-agent-can-be-used-as-post-exploitation-rat-malware/
    - https://www.helpnetsecurity.com/2023/08/02/aws-instances-attackers-access/
author: Muhammad Faisal
date: 2023-08-02
tags:
    - attack.command-and-control
    - attack.persistence
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\amazon-ssm-agent.exe'
        CommandLine|contains|all:
            - '-register '
            - '-code '
            - '-id '
            - '-region '
    condition: selection
falsepositives:
    - Legitimate activity of system administrators
level: medium
```
