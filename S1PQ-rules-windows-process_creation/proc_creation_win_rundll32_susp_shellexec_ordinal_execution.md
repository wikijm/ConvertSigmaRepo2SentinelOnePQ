```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.cmdline contains "SHELL32.DLL" and (src.process.cmdline contains "#568" or src.process.cmdline contains "#570" or src.process.cmdline contains "#572" or src.process.cmdline contains "#576")) and (((src.process.cmdline contains "comspec" or src.process.cmdline contains "iex" or src.process.cmdline contains "Invoke-" or src.process.cmdline contains "msiexec" or src.process.cmdline contains "odbcconf" or src.process.cmdline contains "regsvr32") or (src.process.cmdline contains "\\Desktop\\" or src.process.cmdline contains "\\ProgramData\\" or src.process.cmdline contains "\\Temp\\" or src.process.cmdline contains "\\Users\\Public\\")) or (tgt.process.image.path contains "\\bash.exe" or tgt.process.image.path contains "\\bitsadmin.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\curl.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\msiexec.exe" or tgt.process.image.path contains "\\msxsl.exe" or tgt.process.image.path contains "\\odbcconf.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\wmic.exe" or tgt.process.image.path contains "\\wscript.exe"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious ShellExec_RunDLL Call Via Ordinal
id: 8823e85d-31d8-473e-b7f4-92da070f0fc6
related:
    - id: d87bd452-6da1-456e-8155-7dc988157b7d
      type: derived
status: test
description: |
    Detects suspicious call to the "ShellExec_RunDLL" exported function of SHELL32.DLL through the ordinal number to launch other commands.
    Adversary might only use the ordinal number in order to bypass existing detection that alert on usage of ShellExec_RunDLL on CommandLine.
references:
    - https://redcanary.com/blog/raspberry-robin/
    - https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/
    - https://github.com/SigmaHQ/sigma/issues/1009
    - https://strontic.github.io/xcyclopedia/library/shell32.dll-65DA072F25DE83D9F83653E3FEA3644D.html
author: Swachchhanda Shrawan Poudel
date: 2024-12-01
tags:
    - attack.defense-evasion
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent_img:
        ParentCommandLine|contains: 'SHELL32.DLL'
    selection_parent_ordinal:
        ParentCommandLine|contains:
            # Note: The ordinal number may differ depending on the DLL version
            # Example: rundll32 SHELL32.DLL,#572 "cmd.exe" "/c calc.exe"
            - '#568'
            - '#570'
            - '#572'
            - '#576'
    selection_susp_cli_parent:
        # Note: Add additional binaries and suspicious paths to increase coverage
        - ParentCommandLine|contains:
              - 'comspec'
              - 'iex'
              - 'Invoke-'
              - 'msiexec'
              - 'odbcconf'
              - 'regsvr32'
        - ParentCommandLine|contains:
              - '\Desktop\'
              - '\ProgramData\'
              - '\Temp\'
              - '\Users\Public\'
    selection_susp_child_img:
        Image|endswith:
            - '\bash.exe'
            - '\bitsadmin.exe'
            - '\cmd.exe'
            - '\cscript.exe'
            - '\curl.exe'
            - '\mshta.exe'
            - '\msiexec.exe'
            - '\msxsl.exe'
            - '\odbcconf.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\schtasks.exe'
            - '\wmic.exe'
            - '\wscript.exe'
    condition: all of selection_parent_* and 1 of selection_susp_*
falsepositives:
    - Unknown
level: high
```
