```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/dsenableroot" and (not tgt.process.cmdline contains " -d ")))
```


# Original Sigma Rule:
```yaml
title: Root Account Enable Via Dsenableroot
id: 821bcf4d-46c7-4b87-bc57-9509d3ba7c11
status: test
description: Detects attempts to enable the root account via "dsenableroot"
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/b27a3cb25025161d49ac861cb216db68c46a3537/atomics/T1078.003/T1078.003.md
    - https://github.com/elastic/detection-rules/blob/4312d8c9583be524578a14fe6295c3370b9a9307/rules/macos/persistence_enable_root_account.toml
    - https://ss64.com/osx/dsenableroot.html
author: Sohan G (D4rkCiph3r)
date: 2023-08-22
tags:
    - attack.t1078
    - attack.t1078.001
    - attack.t1078.003
    - attack.initial-access
    - attack.persistence
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/dsenableroot'
    filter_main_disable:
        CommandLine|contains: ' -d '
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
