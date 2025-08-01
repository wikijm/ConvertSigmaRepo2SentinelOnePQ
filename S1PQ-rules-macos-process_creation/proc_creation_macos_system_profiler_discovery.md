```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/system_profiler" or tgt.process.cmdline contains "system_profiler") and (tgt.process.cmdline contains "SPApplicationsDataType" or tgt.process.cmdline contains "SPHardwareDataType" or tgt.process.cmdline contains "SPNetworkDataType" or tgt.process.cmdline contains "SPUSBDataType")))
```


# Original Sigma Rule:
```yaml
title: System Information Discovery Using System_Profiler
id: 4809c683-059b-4935-879d-36835986f8cf
status: test
description: |
    Detects the execution of "system_profiler" with specific "Data Types" that have been seen being used by threat actors and malware. It provides system hardware and software configuration information.
    This process is primarily used for system information discovery. However, "system_profiler" can also be used to determine if virtualization software is being run for defense evasion purposes.
references:
    - https://www.trendmicro.com/en_za/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html
    - https://www.sentinelone.com/wp-content/uploads/pdf-gen/1630910064/20-common-tools-techniques-used-by-macos-threat-actors-malware.pdf
    - https://ss64.com/mac/system_profiler.html
    - https://objective-see.org/blog/blog_0x62.html
    - https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
    - https://gist.github.com/nasbench/9a1ba4bc7094ea1b47bc42bf172961af
author: Stephen Lincoln `@slincoln_aiq` (AttackIQ)
date: 2024-01-02
tags:
    - attack.discovery
    - attack.defense-evasion
    - attack.t1082
    - attack.t1497.001
logsource:
    product: macos
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '/system_profiler'
        - CommandLine|contains: 'system_profiler'
    selection_cmd:
        # Note: This list is based on CTI reporting. Threat actors might use other data types. Please refere to https://gist.github.com/nasbench/9a1ba4bc7094ea1b47bc42bf172961af for a full list
        CommandLine|contains:
            - 'SPApplicationsDataType'
            - 'SPHardwareDataType'
            - 'SPNetworkDataType'
            - 'SPUSBDataType'
    condition: all of selection_*
falsepositives:
    - Legitimate administrative activities
level: medium
```
