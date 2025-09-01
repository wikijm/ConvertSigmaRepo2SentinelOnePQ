```sql
// Translated content (automatically translated on 01-09-2025 01:26:18):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.cmdline contains "osacompile" and tgt.process.cmdline contains "curl"))
```


# Original Sigma Rule:
```yaml
title: Potential In-Memory Download And Compile Of Payloads
id: 13db8d2e-7723-4c2c-93c1-a4d36994f7ef
status: test
description: Detects potential in-memory downloading and compiling of applets using curl and osacompile as seen used by XCSSET malware
references:
    - https://redcanary.com/blog/mac-application-bundles/
author: Sohan G (D4rkCiph3r), Red Canary (idea)
date: 2023-08-22
tags:
    - attack.command-and-control
    - attack.execution
    - attack.t1059.007
    - attack.t1105
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        CommandLine|contains|all:
            - 'osacompile'
            - 'curl'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
