```sql
// Translated content (automatically translated on 09-08-2025 01:21:07):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/csrutil" and tgt.process.cmdline contains "status"))
```


# Original Sigma Rule:
```yaml
title: System Integrity Protection (SIP) Enumeration
id: 53821412-17b0-4147-ade0-14faae67d54b
status: test
description: |
    Detects the use of csrutil to view the Configure System Integrity Protection (SIP) status. This technique is used in post-exploit scenarios.
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
        CommandLine|contains: 'status'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: low
```
