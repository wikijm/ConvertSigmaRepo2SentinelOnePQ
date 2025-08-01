```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\3proxy.exe" or tgt.process.displayName="3proxy - tiny proxy server" or tgt.process.cmdline contains ".exe -i127.0.0.1 -p"))
```


# Original Sigma Rule:
```yaml
title: PUA - 3Proxy Execution
id: f38a82d2-fba3-4781-b549-525efbec8506
status: test
description: Detects the use of 3proxy, a tiny free proxy server
references:
    - https://github.com/3proxy/3proxy
    - https://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
author: Florian Roth (Nextron Systems)
date: 2022-09-13
modified: 2023-02-21
tags:
    - attack.command-and-control
    - attack.t1572
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\3proxy.exe'
    selection_pe:
        Description: '3proxy - tiny proxy server'
    selection_params: # param combos seen in the wild
        CommandLine|contains: '.exe -i127.0.0.1 -p'
    condition: 1 of selection_*
falsepositives:
    - Administrative activity
level: high
```
