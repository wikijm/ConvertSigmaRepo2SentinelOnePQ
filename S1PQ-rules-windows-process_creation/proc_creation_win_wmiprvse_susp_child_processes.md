```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\wbem\WmiPrvSE.exe" and ((tgt.process.image.path contains "\certutil.exe" or tgt.process.image.path contains "\cscript.exe" or tgt.process.image.path contains "\mshta.exe" or tgt.process.image.path contains "\msiexec.exe" or tgt.process.image.path contains "\regsvr32.exe" or tgt.process.image.path contains "\rundll32.exe" or tgt.process.image.path contains "\verclsid.exe" or tgt.process.image.path contains "\wscript.exe") or (tgt.process.image.path contains "\cmd.exe" and (tgt.process.cmdline contains "cscript" or tgt.process.cmdline contains "mshta" or tgt.process.cmdline contains "powershell" or tgt.process.cmdline contains "pwsh" or tgt.process.cmdline contains "regsvr32" or tgt.process.cmdline contains "rundll32" or tgt.process.cmdline contains "wscript"))) and (not (tgt.process.image.path contains "\WerFault.exe" or tgt.process.image.path contains "\WmiPrvSE.exe" or (tgt.process.image.path contains "\msiexec.exe" and tgt.process.cmdline contains "/i ")))))
```


# Original Sigma Rule:
```yaml
title: Suspicious WmiPrvSE Child Process
id: 8a582fe2-0882-4b89-a82a-da6b2dc32937
related:
    - id: 692f0bec-83ba-4d04-af7e-e884a96059b6
      type: similar
    - id: d21374ff-f574-44a7-9998-4a8c8bf33d7d
      type: similar
    - id: 18cf6cf0-39b0-4c22-9593-e244bdc9a2d4
      type: obsolete
status: test
description: Detects suspicious and uncommon child processes of WmiPrvSE
references:
    - https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
    - https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/02bcbfc2bfb8b4da601bb30de0344ae453aa1afe/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml
    - https://blog.osarmor.com/319/onenote-attachment-delivers-asyncrat-malware/
    - https://twitter.com/ForensicITGuy/status/1334734244120309760
author: Vadim Khrykov (ThreatIntel), Cyb3rEng, Florian Roth (Nextron Systems)
date: 2021-08-23
modified: 2023-11-10
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1047
    - attack.t1204.002
    - attack.t1218.010
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: '\wbem\WmiPrvSE.exe'
    selection_children_1:
        # TODO: Add more LOLBINs or suspicious processes that make sens in your environment
        Image|endswith:
            - '\certutil.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\msiexec.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\verclsid.exe'
            - '\wscript.exe'
    selection_children_2:
        # This is in a separate selection due to the nature of FP generated with CMD
        Image|endswith: '\cmd.exe'
        CommandLine|contains:
            - 'cscript'
            - 'mshta'
            - 'powershell'
            - 'pwsh'
            - 'regsvr32'
            - 'rundll32'
            - 'wscript'
    filter_main_werfault:
        Image|endswith: '\WerFault.exe'
    filter_main_wmiprvse:
        Image|endswith: '\WmiPrvSE.exe' # In some legitimate case WmiPrvSE was seen spawning itself
    filter_main_msiexec:
        Image|endswith: '\msiexec.exe'
        CommandLine|contains: '/i '
    condition: selection_parent and 1 of selection_children_* and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
