```sql
// Translated content (automatically translated on 24-05-2025 00:53:32):
event.type="Process Creation" and (endpoint.os="linux" and tgt.process.image.path contains "/nohup")
```


# Original Sigma Rule:
```yaml
title: Nohup Execution
id: e4ffe466-6ff8-48d4-94bd-e32d1a6061e2
status: test
description: Detects usage of nohup which could be leveraged by an attacker to keep a process running or break out from restricted environments
references:
    - https://gtfobins.github.io/gtfobins/nohup/
    - https://en.wikipedia.org/wiki/Nohup
    - https://www.computerhope.com/unix/unohup.htm
author: 'Christopher Peacock @SecurePeacock, SCYTHE @scythe_io'
date: 2022-06-06
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/nohup'
    condition: selection
falsepositives:
    - Administrators or installed processes that leverage nohup
level: medium
```
