```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.displayName="Web Browser Password Viewer" or tgt.process.image.path contains "\WebBrowserPassView.exe"))
```


# Original Sigma Rule:
```yaml
title: PUA - WebBrowserPassView Execution
id: d0dae994-26c6-4d2d-83b5-b3c8b79ae513
status: test
description: Detects the execution of WebBrowserPassView.exe. A password recovery tool that reveals the passwords stored by the following Web browsers, Internet Explorer (Version 4.0 - 11.0), Mozilla Firefox (All Versions), Google Chrome, Safari, and Opera
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1555.003/T1555.003.md
author: frack113
date: 2022-08-20
modified: 2023-02-14
tags:
    - attack.credential-access
    - attack.t1555.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Description: 'Web Browser Password Viewer'
        - Image|endswith: '\WebBrowserPassView.exe'
    condition: selection
falsepositives:
    - Legitimate use
level: medium
```
