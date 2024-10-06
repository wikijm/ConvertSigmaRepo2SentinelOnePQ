```sql
// Translated content (automatically translated on 06-10-2024 07:02:16):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\runexehelper.exe")
```


# Original Sigma Rule:
```yaml
title: Lolbin Runexehelper Use As Proxy
id: cd71385d-fd9b-4691-9b98-2b1f7e508714
status: test
description: Detect usage of the "runexehelper.exe" binary as a proxy to launch other programs
references:
    - https://twitter.com/0gtweet/status/1206692239839289344
    - https://lolbas-project.github.io/lolbas/Binaries/Runexehelper/
author: frack113
date: 2022-12-29
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\runexehelper.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```