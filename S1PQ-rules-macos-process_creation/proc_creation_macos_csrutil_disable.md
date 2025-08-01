```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/csrutil" and tgt.process.cmdline contains "disable"))
```


# Original Sigma Rule:
```yaml
title: System Integrity Protection (SIP) Disabled
id: 3603f18a-ec15-43a1-9af2-d196c8a7fec6
status: test
description: |
    Detects the use of csrutil to disable the Configure System Integrity Protection (SIP). This technique is used in post-exploit scenarios.
references:
    - https://ss64.com/osx/csrutil.html
    - https://objective-see.org/blog/blog_0x6D.html
    - https://www.welivesecurity.com/2017/10/20/osx-proton-supply-chain-attack-elmedia/
    - https://www.virustotal.com/gui/file/05a2adb266ec6c0ba9ed176d87d8530e71e845348c13caf9f60049760c312cd3/behavior
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2024-01-02
tags:
    - attack.discovery
    - attack.t1518.001
logsource:
    product: macos
    category: process_creation
detection:
    # VT Query: behavior_processes:"csrutil status" p:5+ type:mac
    selection:
        Image|endswith: '/csrutil'
        CommandLine|contains: 'disable'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
