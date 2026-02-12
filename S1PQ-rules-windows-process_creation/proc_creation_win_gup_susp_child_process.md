```sql
// Translated content (automatically translated on 12-02-2026 02:54:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\gup.exe" and ((tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\mshta.exe") or (tgt.process.cmdline contains "bitsadmin" or tgt.process.cmdline contains "certutil" or tgt.process.cmdline contains "curl" or tgt.process.cmdline contains "finger" or tgt.process.cmdline contains "forfiles" or tgt.process.cmdline contains "regsvr32" or tgt.process.cmdline contains "rundll32" or tgt.process.cmdline contains "wget"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Child Process of Notepad++ Updater - GUP.Exe
id: bb0e87ce-c89f-4857-84fa-095e4483e9cb
status: experimental
description: |
    Detects suspicious child process creation by the Notepad++ updater process (gup.exe).
    This could indicate potential exploitation of the updater component to deliver unwanted malware.
references:
    - https://notepad-plus-plus.org/news/v889-released/
    - https://www.heise.de/en/news/Notepad-updater-installed-malware-11109726.html
    - https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
    - https://www.validin.com/blog/exploring_notepad_plus_plus_network_indicators/
    - https://securelist.com/notepad-supply-chain-attack/118708/
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2026-02-03
tags:
    - attack.collection
    - attack.credential-access
    - attack.t1195.002
    - attack.initial-access
    - attack.t1557
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\gup.exe'
    selection_child_img:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cscript.exe'
            - '\wscript.exe'
            - '\mshta.exe'
    selection_child_cli:
        CommandLine|contains:
            - 'bitsadmin'
            - 'certutil'
            - 'curl'
            - 'finger'
            - 'forfiles'
            - 'regsvr32'
            - 'rundll32'
            - 'wget'
    condition: selection_parent and 1 of selection_child_*
falsepositives:
    - Unlikely
level: high
```
