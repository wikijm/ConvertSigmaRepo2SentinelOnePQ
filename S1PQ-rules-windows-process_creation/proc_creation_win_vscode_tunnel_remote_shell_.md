```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\servers\\Stable-" and src.process.image.path contains "\\server\\node.exe" and src.process.cmdline contains ".vscode-server") and (((tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe") and tgt.process.cmdline contains "\\terminal\\browser\\media\\shellIntegration.ps1") or (tgt.process.image.path contains "\\wsl.exe" or tgt.process.image.path contains "\\bash.exe"))))
```


# Original Sigma Rule:
```yaml
title: Visual Studio Code Tunnel Shell Execution
id: f4a623c2-4ef5-4c33-b811-0642f702c9f1
status: test
description: Detects the execution of a shell (powershell, bash, wsl...) via Visual Studio Code tunnel. Attackers can abuse this functionality to establish a C2 channel and execute arbitrary commands on the system.
references:
    - https://ipfyx.fr/post/visual-studio-code-tunnel/
    - https://badoption.eu/blog/2023/01/31/code_c2.html
    - https://code.visualstudio.com/docs/remote/tunnels
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-10-25
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|contains: '\servers\Stable-'
        ParentImage|endswith: '\server\node.exe'
        ParentCommandLine|contains: '.vscode-server' # Technically one can host its own local server instead of using the VsCode one. And that would probably change the name (requires further research)
    # Note: Child processes (ie: shells) can be whatever technically (with some efforts)
    selection_child_1:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains: '\terminal\browser\media\shellIntegration.ps1'
    selection_child_2:
        Image|endswith:
            - '\wsl.exe'
            - '\bash.exe'
    condition: selection_parent and 1 of selection_child_*
falsepositives:
    - Legitimate use of Visual Studio Code tunnel and running code from there
level: medium
```
