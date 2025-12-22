```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\Velociraptor.exe" and ((tgt.process.cmdline contains "code.exe" and tgt.process.cmdline contains "tunnel" and tgt.process.cmdline contains "--accept-server-license-terms") or (tgt.process.cmdline contains "msiexec" and tgt.process.cmdline contains "/i" and tgt.process.cmdline contains "http") or ((tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\powershell_ise.exe" or tgt.process.image.path contains "\\pwsh.exe") and (tgt.process.cmdline contains "Invoke-WebRequest " or tgt.process.cmdline contains "IWR " or tgt.process.cmdline contains ".DownloadFile" or tgt.process.cmdline contains ".DownloadString")))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Velociraptor Child Process
id: 4bc90587-e6ca-4b41-be0b-ed4d04e4ed0c
status: experimental
description: Detects the suspicious use of the Velociraptor DFIR tool to execute other tools or download additional payloads, as seen in a campaign where it was abused for remote access and to stage further attacks.
references:
    - https://news.sophos.com/en-us/2025/08/26/velociraptor-incident-response-tool-abused-for-remote-access/
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-08-29
tags:
    - attack.command-and-control
    - attack.persistence
    - attack.defense-evasion
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\Velociraptor.exe'
    selection_child_vscode_tunnel:
        CommandLine|contains|all:
            - 'code.exe'
            - 'tunnel'
            - '--accept-server-license-terms'
    selection_child_msiexec:
        CommandLine|contains|all:
            - 'msiexec'
            - '/i'
            - 'http'
    selection_child_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\powershell_ise.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - 'Invoke-WebRequest '
            - 'IWR '
            - '.DownloadFile'
            - '.DownloadString'
    # Add more child process patterns as needed
    condition: selection_parent and 1 of selection_child_*
falsepositives:
    - Legitimate administrators or incident responders might use Velociraptor to execute scripts or tools. However, the combination of Velociraptor spawning these specific processes with these command lines is suspicious. Tuning may be required to exclude known administrative actions or specific scripts.
level: high
```
