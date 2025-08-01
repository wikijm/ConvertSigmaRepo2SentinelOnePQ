```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "awk" or tgt.process.image.path contains "/cat" or tgt.process.image.path contains "grep" or tgt.process.image.path contains "/head" or tgt.process.image.path contains "/less" or tgt.process.image.path contains "/more" or tgt.process.image.path contains "/nl" or tgt.process.image.path contains "/tail") and (tgt.process.cmdline contains "/proc/2/" or (tgt.process.cmdline contains "/proc/" and (tgt.process.cmdline contains "/cgroup" or tgt.process.cmdline contains "/sched")))))
```


# Original Sigma Rule:
```yaml
title: Container Residence Discovery Via Proc Virtual FS
id: 746c86fb-ccda-4816-8997-01386263acc4
status: test
description: Detects potential container discovery via listing of certain kernel features in the "/proc" virtual filesystem
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
    selection_tools:
        Image|endswith:
            - 'awk'
            - '/cat'
            - 'grep'
            - '/head'
            - '/less'
            - '/more'
            - '/nl'
            - '/tail'
    selection_procfs_kthreadd:  # outside containers, PID 2 == kthreadd
        CommandLine|contains: '/proc/2/'
    selection_procfs_target:
        CommandLine|contains: '/proc/'
        CommandLine|endswith:
            - '/cgroup'  # cgroups end in ':/' outside containers
            - '/sched'   # PID mismatch when run in containers
    condition: selection_tools and 1 of selection_procfs_*
falsepositives:
    - Legitimate system administrator usage of these commands
    - Some container tools or deployments may use these techniques natively to determine how they proceed with execution, and will need to be filtered
level: low
```
