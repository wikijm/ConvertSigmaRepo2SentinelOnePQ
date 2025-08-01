```sql
// Translated content (automatically translated on 02-08-2025 02:10:48):
event.category="DNS" and (endpoint.os="windows" and event.dns.request contains ".tunnels.api.visualstudio.com")
```


# Original Sigma Rule:
```yaml
title: DNS Query To Visual Studio Code Tunnels Domain
id: b3e6418f-7c7a-4fad-993a-93b65027a9f1
related:
    - id: 9501f8e6-8e3d-48fc-a8a6-1089dd5d7ef4 # Net Connection DevTunnels
      type: similar
    - id: 4b657234-038e-4ad5-997c-4be42340bce4 # Net Connection VsCode
      type: similar
    - id: 1cb0c6ce-3d00-44fc-ab9c-6d6d577bf20b # DNS DevTunnels
      type: similar
status: test
description: |
    Detects DNS query requests to Visual Studio Code tunnel domains. Attackers can abuse that feature to establish a reverse shell or persistence on a machine.
references:
    - https://ipfyx.fr/post/visual-studio-code-tunnel/
    - https://badoption.eu/blog/2023/01/31/code_c2.html
    - https://cydefops.com/vscode-data-exfiltration
author: citron_ninja
date: 2023-10-25
modified: 2023-11-20
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith: '.tunnels.api.visualstudio.com'
    condition: selection
falsepositives:
    - Legitimate use of Visual Studio Code tunnel will also trigger this.
level: medium
```
