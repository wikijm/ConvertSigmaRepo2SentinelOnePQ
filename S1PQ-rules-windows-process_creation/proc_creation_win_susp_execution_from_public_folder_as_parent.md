```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains ":\\Users\\Public\\" and ((tgt.process.image.path contains "\\bitsadmin.exe" or tgt.process.image.path contains "\\certutil.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\wscript.exe") or (tgt.process.cmdline contains "bitsadmin" or tgt.process.cmdline contains "certutil" or tgt.process.cmdline contains "cscript" or tgt.process.cmdline contains "mshta" or tgt.process.cmdline contains "powershell" or tgt.process.cmdline contains "regsvr32" or tgt.process.cmdline contains "rundll32" or tgt.process.cmdline contains "wscript"))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Execution From Parent Process In Public Folder
id: 69bd9b97-2be2-41b6-9816-fb08757a4d1a
status: test
description: |
    Detects a potentially suspicious execution of a parent process located in the "\Users\Public" folder executing a child process containing references to shell or scripting binaries and commandlines.
references:
    - https://redcanary.com/blog/blackbyte-ransomware/
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-02-25
modified: 2024-07-12
tags:
    - attack.defense-evasion
    - attack.execution
    - attack.t1564
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|contains: ':\Users\Public\'
    selection_child:
        - Image|endswith:
              - '\bitsadmin.exe'
              - '\certutil.exe'
              - '\cmd.exe'
              - '\cscript.exe'
              - '\mshta.exe'
              - '\powershell.exe'
              - '\pwsh.exe'
              - '\regsvr32.exe'
              - '\rundll32.exe'
              - '\wscript.exe'
        - CommandLine|contains:
              - 'bitsadmin'
              - 'certutil'
              - 'cscript'
              - 'mshta'
              - 'powershell'
              - 'regsvr32'
              - 'rundll32'
              - 'wscript'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
