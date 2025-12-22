```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains " -u system " or tgt.process.cmdline contains " --user system " or tgt.process.cmdline contains " -u NT" or tgt.process.cmdline contains " -u \"NT" or tgt.process.cmdline contains " -u 'NT" or tgt.process.cmdline contains " --system " or tgt.process.cmdline contains " -u administrator ") and (tgt.process.cmdline contains " -c cmd" or tgt.process.cmdline contains " -c \"cmd" or tgt.process.cmdline contains " -c powershell" or tgt.process.cmdline contains " -c \"powershell" or tgt.process.cmdline contains " --command cmd" or tgt.process.cmdline contains " --command powershell" or tgt.process.cmdline contains " -c whoami" or tgt.process.cmdline contains " -c wscript" or tgt.process.cmdline contains " -c cscript")))
```


# Original Sigma Rule:
```yaml
title: Suspicious RunAs-Like Flag Combination
id: 50d66fb0-03f8-4da0-8add-84e77d12a020
status: test
description: Detects suspicious command line flags that let the user set a target user and command as e.g. seen in PsExec-like tools
references:
    - https://www.trendmicro.com/en_us/research/22/k/hack-the-real-box-apt41-new-subgroup-earth-longzhi.html
author: Florian Roth (Nextron Systems)
date: 2022-11-11
tags:
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection_user:
        CommandLine|contains:
            - ' -u system '
            - ' --user system '
            - ' -u NT'
            - ' -u "NT'
            - " -u 'NT"
            - ' --system '
            - ' -u administrator '
    selection_command:
        CommandLine|contains:
            - ' -c cmd'
            - ' -c "cmd'
            - ' -c powershell'
            - ' -c "powershell'
            - ' --command cmd'
            - ' --command powershell'
            - ' -c whoami'
            - ' -c wscript'
            - ' -c cscript'
    condition: all of selection*
falsepositives:
    - Unknown
level: medium
```
