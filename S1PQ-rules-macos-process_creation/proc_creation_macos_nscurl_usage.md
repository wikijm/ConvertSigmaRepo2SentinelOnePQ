```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/nscurl" and (tgt.process.cmdline contains "--download " or tgt.process.cmdline contains "--download-directory " or tgt.process.cmdline contains "--output " or tgt.process.cmdline contains "-dir " or tgt.process.cmdline contains "-dl " or tgt.process.cmdline contains "-ld" or tgt.process.cmdline contains "-o ")))
```


# Original Sigma Rule:
```yaml
title: File Download Via Nscurl - MacOS
id: 6d8a7cf1-8085-423b-b87d-7e880faabbdf
status: test
description: Detects the execution of the nscurl utility in order to download files.
references:
    - https://www.loobins.io/binaries/nscurl/
    - https://www.agnosticdev.com/content/how-diagnose-app-transport-security-issues-using-nscurl-and-openssl
    - https://gist.github.com/nasbench/ca6ef95db04ae04ffd1e0b1ce709cadd
author: Daniel Cortez
date: 2024-06-04
tags:
    - attack.defense-evasion
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/nscurl'
        CommandLine|contains:
            - '--download '
            - '--download-directory '
            - '--output '
            - '-dir '
            - '-dl '
            - '-ld'
            - '-o '
    condition: selection
falsepositives:
    - Legitimate usage of nscurl by administrators and users.
level: medium
```
