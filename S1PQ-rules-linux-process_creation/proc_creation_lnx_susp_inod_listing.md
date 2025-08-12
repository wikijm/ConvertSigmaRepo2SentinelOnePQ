```sql
// Translated content (automatically translated on 12-08-2025 00:57:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/ls" and (tgt.process.cmdline="* -*i*" and tgt.process.cmdline="* -*d*") and tgt.process.cmdline contains " /"))
```


# Original Sigma Rule:
```yaml
title: Potential Container Discovery Via Inodes Listing
id: 43e26eb5-cd58-48d1-8ce9-a273f5d298d8
status: test
description: Detects listing of the inodes of the "/" directory to determine if the we are running inside of a container.
references:
    - https://blog.skyplabs.net/posts/container-detection/
    - https://stackoverflow.com/questions/20010199/how-to-determine-if-a-process-runs-inside-lxc-docker
tags:
    - attack.discovery
    - attack.t1082
author: Seth Hanford
date: 2023-08-23
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        # inode outside containers low, inside high
        Image|endswith: '/ls'
        CommandLine|contains|all:
            - ' -*i'              # -i finds inode number
            - ' -*d'              # -d gets directory itself, not contents
        CommandLine|endswith: ' /'
    condition: selection
falsepositives:
    - Legitimate system administrator usage of these commands
    - Some container tools or deployments may use these techniques natively to determine how they proceed with execution, and will need to be filtered
level: low
```
