```sql
// Translated content (automatically translated on 10-09-2026 04:17:17):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\nxc.exe" and (tgt.process.cmdline contains " ftp " or tgt.process.cmdline contains " ldap " or tgt.process.cmdline contains " mssql " or tgt.process.cmdline contains " nfs " or tgt.process.cmdline contains " rdp " or tgt.process.cmdline contains " smb " or tgt.process.cmdline contains " ssh " or tgt.process.cmdline contains " vnc " or tgt.process.cmdline contains " winrm " or tgt.process.cmdline contains " wmi ")))
```


# Original Sigma Rule:
```yaml
title: HackTool - NetExec Execution
id: 7638e5fe-600c-4289-a968-f49dd537ec7d
status: experimental
description: |
    Detects execution of the hacktool NetExec.
    NetExec (formerly CrackMapExec) is a widely used post-exploitation tool designed for Active Directory penetration testing and network enumeration
    In enterprise environments, the use of NetExec is considered suspicious or potentially malicious because it enables attackers to enumerate hosts, exploit network services, and move laterally across systems.
    Threat actors and red teams commonly use NetExec to identify vulnerable systems, harvest credentials, and execute commands remotely.
references:
    - https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/
    - https://github.com/Pennyw0rth/NetExec
    - https://www.netexec.wiki/
author: Chirag Damani
date: 2026-03-29
tags:
    - attack.discovery
    - attack.t1018
    - attack.lateral-movement
    - attack.t1021
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\nxc.exe'
        CommandLine|contains:
            - ' ftp '
            - ' ldap '
            - ' mssql '
            - ' nfs '
            - ' rdp '
            - ' smb '
            - ' ssh '
            - ' vnc '
            - ' winrm '
            - ' wmi '
    condition: selection
falsepositives:
    - Legitimate use of NetExec by security professionals or system administrators for network assessment and management.
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_hktl_netexec/info.yml
```
