```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}" or ((tgt.process.cmdline contains "explorer.exe") and (tgt.process.cmdline contains " -root," or tgt.process.cmdline contains " /root," or tgt.process.cmdline contains " –root," or tgt.process.cmdline contains " —root," or tgt.process.cmdline contains " ―root,"))))
```


# Original Sigma Rule:
```yaml
title: Explorer Process Tree Break
id: 949f1ffb-6e85-4f00-ae1e-c3c5b190d605
status: test
description: |
  Detects a command line process that uses explorer.exe to launch arbitrary commands or binaries,
  which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer spawning from "svchost"
references:
    - https://twitter.com/CyberRaiju/status/1273597319322058752
    - https://twitter.com/bohops/status/1276357235954909188?s=12
    - https://twitter.com/nas_bench/status/1535322450858233858
    - https://securityboulevard.com/2019/09/deobfuscating-ostap-trickbots-34000-line-javascript-downloader/
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems), @gott_cyber
date: 2019-06-29
modified: 2024-06-04
tags:
    - attack.defense-evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # See CLSID_SeparateMultipleProcessExplorerHost in the registry for reference
        - CommandLine|contains: '/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}' # This will catch, the new explorer spawning which indicates a process/tree break. But you won't be able to catch the executing process. For that you need historical data
        # There exists almost infinite possibilities to spawn from explorer. The "/root" flag is just an example
        # It's better to have the ability to look at the process tree and look for explorer processes with "weird" flags to be able to catch this technique.
        - CommandLine|contains|all|windash:
              - 'explorer.exe'
              - ' /root,'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
