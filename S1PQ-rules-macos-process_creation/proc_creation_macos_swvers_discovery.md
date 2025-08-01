```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/sw_vers" and (tgt.process.cmdline contains "-buildVersion" or tgt.process.cmdline contains "-productName" or tgt.process.cmdline contains "-productVersion")))
```


# Original Sigma Rule:
```yaml
title: System Information Discovery Using sw_vers
id: 5de06a6f-673a-4fc0-8d48-bcfe3837b033
status: test
description: Detects the use of "sw_vers" for system information discovery
references:
    - https://www.virustotal.com/gui/file/d3fa64f63563fe958b75238742d1e473800cb5f49f5cb79d38d4aa3c93709026/behavior
    - https://www.virustotal.com/gui/file/03b71eaceadea05bc0eea5cddecaa05f245126d6b16cfcd0f3ba0442ac58dab3/behavior
    - https://ss64.com/osx/sw_vers.html
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-12-20
tags:
    - attack.discovery
    - attack.t1082
logsource:
    product: macos
    category: process_creation
detection:
    # VT Query: 'behavior_processes:"sw_vers" and (behavior_processes:"-productVersion" or behavior_processes:"-productName" or behavior_processes:"-buildVersion") tag:dmg p:5+'
    selection_image:
        Image|endswith: '/sw_vers'
    selection_options:
        CommandLine|contains:
            - '-buildVersion'
            - '-productName'
            - '-productVersion'
    condition: all of selection_*
falsepositives:
    - Legitimate administrative activities
level: medium
```
