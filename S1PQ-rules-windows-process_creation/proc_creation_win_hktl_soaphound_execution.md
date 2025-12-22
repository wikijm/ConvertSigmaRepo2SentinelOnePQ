```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains " --buildcache " or tgt.process.cmdline contains " --bhdump " or tgt.process.cmdline contains " --certdump " or tgt.process.cmdline contains " --dnsdump ") and (tgt.process.cmdline contains " -c " or tgt.process.cmdline contains " --cachefilename " or tgt.process.cmdline contains " -o " or tgt.process.cmdline contains " --outputdirectory")))
```


# Original Sigma Rule:
```yaml
title: HackTool - SOAPHound Execution
id: e92a4287-e072-4a40-9739-370c106bb750
status: test
description: |
    Detects the execution of SOAPHound, a .NET tool for collecting Active Directory data, using specific command-line arguments that may indicate an attempt to extract sensitive AD information.
references:
    - https://github.com/FalconForceTeam/SOAPHound
    - https://medium.com/falconforce/soaphound-tool-to-collect-active-directory-data-via-adws-165aca78288c
author: '@kostastsale'
date: 2024-01-26
tags:
    - attack.discovery
    - attack.t1087
logsource:
    product: windows
    category: process_creation
detection:
    selection_1:
        CommandLine|contains:
            - ' --buildcache '
            - ' --bhdump '
            - ' --certdump '
            - ' --dnsdump '
    selection_2:
        CommandLine|contains:
            - ' -c '
            - ' --cachefilename '
            - ' -o '
            - ' --outputdirectory'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
