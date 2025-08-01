```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\node.exe" and (tgt.process.cmdline contains " -e " or tgt.process.cmdline contains " --eval ")) and (tgt.process.cmdline contains ".exec(" and tgt.process.cmdline contains "net.socket" and tgt.process.cmdline contains ".connect" and tgt.process.cmdline contains "child_process")))
```


# Original Sigma Rule:
```yaml
title: Potential Arbitrary Code Execution Via Node.EXE
id: 6640f31c-01ad-49b5-beb5-83498a5cd8bd
status: test
description: Detects the execution node.exe which is shipped with multiple software such as VMware, Adobe...etc. In order to execute arbitrary code. For example to establish reverse shell as seen in Log4j attacks...etc
references:
    - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
    - https://www.sprocketsecurity.com/resources/crossing-the-log4j-horizon-a-vulnerability-with-no-return
    - https://www.rapid7.com/blog/post/2022/01/18/active-exploitation-of-vmware-horizon-servers/
    - https://nodejs.org/api/cli.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-09
modified: 2023-02-03
tags:
    - attack.defense-evasion
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection_main:
        Image|endswith: '\node.exe'
        CommandLine|contains:
            - ' -e '
            - ' --eval '
    # Add more pattern of abuse as actions
    selection_action_reverse_shell:
        CommandLine|contains|all:
            - '.exec('
            - 'net.socket'
            - '.connect'
            - 'child_process'
    condition: selection_main and 1 of selection_action_*
falsepositives:
    - Unlikely
level: high
```
