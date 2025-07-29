```sql
// Translated content (automatically translated on 29-07-2025 02:32:58):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\explorer.exe" and tgt.process.image.path contains "\notepad.exe" and (tgt.process.cmdline="*password*.txt" or tgt.process.cmdline="*password*.csv" or tgt.process.cmdline="*password*.doc" or tgt.process.cmdline="*password*.xls")))
```


# Original Sigma Rule:
```yaml
title: Notepad Password Files Discovery
id: 3b4e950b-a3ea-44d3-877e-432071990709
status: experimental
description: Detects the execution of Notepad to open a file that has the string "password" which may indicate unauthorized access to credentials or suspicious activity.
references:
    - https://thedfirreport.com/2025/02/24/confluence-exploit-leads-to-lockbit-ransomware/
    - https://intel.thedfirreport.com/eventReports/view/57  # Private Report
author: 'The DFIR Report'
tags:
    - attack.discovery
    - attack.t1083
date: 2025-02-21
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\explorer.exe'
        Image|endswith: '\notepad.exe'
        CommandLine|endswith:
        # Note: Commandline to contain a file with the string password and a specific extension
            - 'password*.txt'
            - 'password*.csv'
            - 'password*.doc'
            - 'password*.xls'
    condition: selection
falsepositives:
    - Legitimate use of opening files from remote hosts by administrators or users. However, storing passwords in text readable format could potentially be a violation of the organization's policy. Any match should be investigated further.
level: low
```
