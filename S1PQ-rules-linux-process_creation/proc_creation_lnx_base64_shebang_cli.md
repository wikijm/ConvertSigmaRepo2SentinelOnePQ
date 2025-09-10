```sql
// Translated content (automatically translated on 10-09-2025 00:51:23):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.cmdline contains "IyEvYmluL2Jhc2" or tgt.process.cmdline contains "IyEvYmluL2Rhc2" or tgt.process.cmdline contains "IyEvYmluL3pza" or tgt.process.cmdline contains "IyEvYmluL2Zpc2" or tgt.process.cmdline contains "IyEvYmluL3No"))
```


# Original Sigma Rule:
```yaml
title: Linux Base64 Encoded Shebang In CLI
id: fe2f9663-41cb-47e2-b954-8a228f3b9dff
status: test
description: Detects the presence of a base64 version of the shebang in the commandline, which could indicate a malicious payload about to be decoded
references:
    - https://www.trendmicro.com/pl_pl/research/20/i/the-evolution-of-malicious-shell-scripts.html
    - https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-15
tags:
    - attack.defense-evasion
    - attack.t1140
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - "IyEvYmluL2Jhc2" # Note: #!/bin/bash"
            - "IyEvYmluL2Rhc2" # Note: #!/bin/dash"
            - "IyEvYmluL3pza" # Note: #!/bin/zsh"
            - "IyEvYmluL2Zpc2" # Note: #!/bin/fish
            - "IyEvYmluL3No" # Note: # !/bin/sh"
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
