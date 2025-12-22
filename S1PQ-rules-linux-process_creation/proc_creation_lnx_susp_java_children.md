```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (src.process.image.path contains "/java" and (tgt.process.cmdline contains "/bin/sh" or tgt.process.cmdline contains "bash" or tgt.process.cmdline contains "dash" or tgt.process.cmdline contains "ksh" or tgt.process.cmdline contains "zsh" or tgt.process.cmdline contains "csh" or tgt.process.cmdline contains "fish" or tgt.process.cmdline contains "curl" or tgt.process.cmdline contains "wget" or tgt.process.cmdline contains "python")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Java Children Processes
id: d292e0af-9a18-420c-9525-ec0ac3936892
status: test
description: Detects java process spawning suspicious children
references:
    - https://www.tecmint.com/different-types-of-linux-shells/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-03
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
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
