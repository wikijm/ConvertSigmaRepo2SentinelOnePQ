```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\\Program Files\\WindowsApps\\" and ((tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\powershell_ise.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\wscript.exe") or (tgt.process.cmdline contains "cmd /c" or tgt.process.cmdline contains "Invoke-" or tgt.process.cmdline contains "Base64")) and (not ((src.process.image.path contains ":\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal" and src.process.image.path contains "\\WindowsTerminal.exe" and (tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\pwsh.exe")) or (src.process.image.path contains "C:\\Program Files\\WindowsApps\\Microsoft.SysinternalsSuite" and tgt.process.image.path contains "\\cmd.exe")))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Windows App Activity
id: f91ed517-a6ba-471d-9910-b3b4a398c0f3
status: test
description: Detects potentially suspicious child process of applications launched from inside the WindowsApps directory. This could be a sign of a rogue ".appx" package installation/execution
references:
    - https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
    - https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-12
modified: 2025-10-07
tags:
    - attack.defense-evasion
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        # GrandParentImage|endswith: '\sihost.exe'
        ParentImage|contains: 'C:\Program Files\WindowsApps\'
    selection_susp_img:
        Image|endswith:
            # You can add more LOLBINs
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\powershell_ise.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\wscript.exe'
    selection_susp_cli:
        # You can add more potentially suspicious keywords
        CommandLine|contains:
            - 'cmd /c'
            - 'Invoke-'
            - 'Base64'
    filter_optional_terminal:
        ParentImage|contains: ':\Program Files\WindowsApps\Microsoft.WindowsTerminal'
        ParentImage|endswith: '\WindowsTerminal.exe'
        # Note: to avoid FP add the default shells and profiles that your WT integrates
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
            - '\pwsh.exe'
    filter_optional_sysinternals:
        ParentImage|startswith: 'C:\Program Files\WindowsApps\Microsoft.SysinternalsSuite'
        Image|endswith: '\cmd.exe'
    condition: selection_parent and 1 of selection_susp_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate packages that make use of external binaries such as Windows Terminal
level: medium
```
