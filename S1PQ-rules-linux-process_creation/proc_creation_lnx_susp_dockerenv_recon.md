```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/cat" or tgt.process.image.path contains "/dir" or tgt.process.image.path contains "/find" or tgt.process.image.path contains "/ls" or tgt.process.image.path contains "/stat" or tgt.process.image.path contains "/test" or tgt.process.image.path contains "grep") and tgt.process.cmdline contains ".dockerenv"))
```


# Original Sigma Rule:
```yaml
title: Docker Container Discovery Via Dockerenv Listing
id: 11701de9-d5a5-44aa-8238-84252f131895
status: test
description: Detects listing or file reading of ".dockerenv" which can be a sing of potential container discovery
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
        Image|endswith:
            # Note: add additional tools and utilities to increase coverage
            - '/cat'
            - '/dir'
            - '/find'
            - '/ls'
            - '/stat'
            - '/test'
            - 'grep'
        CommandLine|endswith: '.dockerenv'
    condition: selection
falsepositives:
    - Legitimate system administrator usage of these commands
    - Some container tools or deployments may use these techniques natively to determine how they proceed with execution, and will need to be filtered
level: low
```
