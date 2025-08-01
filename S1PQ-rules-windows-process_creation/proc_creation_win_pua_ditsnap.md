```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\ditsnap.exe" or tgt.process.cmdline contains "ditsnap.exe"))
```


# Original Sigma Rule:
```yaml
title: PUA - DIT Snapshot Viewer
id: d3b70aad-097e-409c-9df2-450f80dc476b
status: test
description: Detects the use of Ditsnap tool, an inspection tool for Active Directory database, ntds.dit.
references:
    - https://thedfirreport.com/2020/06/21/snatch-ransomware/
    - https://web.archive.org/web/20201124182207/https://github.com/yosqueoy/ditsnap
author: Furkan Caliskan (@caliskanfurkan_)
date: 2020-07-04
modified: 2023-02-21
tags:
    - attack.credential-access
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\ditsnap.exe'
        - CommandLine|contains: 'ditsnap.exe'
    condition: selection
falsepositives:
    - Legitimate admin usage
level: high
```
