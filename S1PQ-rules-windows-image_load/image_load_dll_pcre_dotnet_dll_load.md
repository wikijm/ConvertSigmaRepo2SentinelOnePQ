```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\AppData\Local\Temp\ba9ea7344a4a5f591d6e5dc32a13494b\")
```


# Original Sigma Rule:
```yaml
title: PCRE.NET Package Image Load
id: 84b0a8f3-680b-4096-a45b-e9a89221727c
status: test
description: Detects processes loading modules related to PCRE.NET package
references:
    - https://twitter.com/rbmaslen/status/1321859647091970051
    - https://twitter.com/tifkin_/status/1321916444557365248
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-10-29
modified: 2022-10-09
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|contains: \AppData\Local\Temp\ba9ea7344a4a5f591d6e5dc32a13494b\
    condition: selection
falsepositives:
    - Unknown
level: high
```
