```sql
// Translated content (automatically translated on 15-08-2025 00:58:42):
event.type="Process Creation" and (endpoint.os="linux" and (src.process.image.path contains "/opt/atlassian/confluence/" and src.process.image.path contains "/java" and (tgt.process.cmdline contains "/bin/sh" or tgt.process.cmdline contains "bash" or tgt.process.cmdline contains "dash" or tgt.process.cmdline contains "ksh" or tgt.process.cmdline contains "zsh" or tgt.process.cmdline contains "csh" or tgt.process.cmdline contains "fish" or tgt.process.cmdline contains "curl" or tgt.process.cmdline contains "wget" or tgt.process.cmdline contains "python")))
```


# Original Sigma Rule:
```yaml
title: Atlassian Confluence CVE-2022-26134
id: 7fb14105-530e-4e2e-8cfb-99f7d8700b66
related:
    - id: 245f92e3-c4da-45f1-9070-bc552e06db11
      type: derived
status: test
description: Detects spawning of suspicious child processes by Atlassian Confluence server which may indicate successful exploitation of CVE-2022-26134
references:
    - https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-03
tags:
    - attack.initial-access
    - attack.execution
    - attack.t1190
    - attack.t1059
    - cve.2022-26134
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        # Monitor suspicious child processes spawned by Confluence
        ParentImage|startswith: '/opt/atlassian/confluence/'
        ParentImage|endswith: '/java'
        CommandLine|contains:
            - '/bin/sh'
            - 'bash'
            - 'dash'
            - 'ksh'
            - 'zsh'
            - 'csh'
            - 'fish'
            - 'curl'
            - 'wget'
            - 'python'
    condition: selection
falsepositives:
    - Unknown
level: high
```
