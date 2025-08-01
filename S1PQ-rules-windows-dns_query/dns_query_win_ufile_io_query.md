```sql
// Translated content (automatically translated on 02-08-2025 02:10:48):
event.category="DNS" and (endpoint.os="windows" and event.dns.request contains "ufile.io")
```


# Original Sigma Rule:
```yaml
title: DNS Query To Ufile.io
id: 1cbbeaaf-3c8c-4e4c-9d72-49485b6a176b
related:
    - id: 090ffaad-c01a-4879-850c-6d57da98452d
      type: similar
status: test
description: Detects DNS queries to "ufile.io", which was seen abused by malware and threat actors as a method for data exfiltration
references:
    - https://thedfirreport.com/2021/12/13/diavol-ransomware/
author: yatinwad, TheDFIRReport
date: 2022-06-23
modified: 2023-09-18
tags:
    - attack.exfiltration
    - attack.t1567.002
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|contains: 'ufile.io'
    condition: selection
falsepositives:
    - DNS queries for "ufile" are not malicious by nature necessarily. Investigate the source to determine the necessary actions to take
level: low
```
