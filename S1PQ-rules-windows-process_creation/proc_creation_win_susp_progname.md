```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\CVE-202" or tgt.process.image.path contains "\\CVE202") or (tgt.process.image.path contains "\\poc.exe" or tgt.process.image.path contains "\\artifact.exe" or tgt.process.image.path contains "\\artifact64.exe" or tgt.process.image.path contains "\\artifact_protected.exe" or tgt.process.image.path contains "\\artifact32.exe" or tgt.process.image.path contains "\\artifact32big.exe" or tgt.process.image.path contains "obfuscated.exe" or tgt.process.image.path contains "obfusc.exe" or tgt.process.image.path contains "\\meterpreter")) or (tgt.process.cmdline contains "inject.ps1" or tgt.process.cmdline contains "Invoke-CVE" or tgt.process.cmdline contains "pupy.ps1" or tgt.process.cmdline contains "payload.ps1" or tgt.process.cmdline contains "beacon.ps1" or tgt.process.cmdline contains "PowerView.ps1" or tgt.process.cmdline contains "bypass.ps1" or tgt.process.cmdline contains "obfuscated.ps1" or tgt.process.cmdline contains "obfusc.ps1" or tgt.process.cmdline contains "obfus.ps1" or tgt.process.cmdline contains "obfs.ps1" or tgt.process.cmdline contains "evil.ps1" or tgt.process.cmdline contains "MiniDogz.ps1" or tgt.process.cmdline contains "_enc.ps1" or tgt.process.cmdline contains "\\shell.ps1" or tgt.process.cmdline contains "\\rshell.ps1" or tgt.process.cmdline contains "revshell.ps1" or tgt.process.cmdline contains "\\av.ps1" or tgt.process.cmdline contains "\\av_test.ps1" or tgt.process.cmdline contains "adrecon.ps1" or tgt.process.cmdline contains "mimikatz.ps1" or tgt.process.cmdline contains "\\PowerUp_" or tgt.process.cmdline contains "powerup.ps1" or tgt.process.cmdline contains "\\Temp\\a.ps1" or tgt.process.cmdline contains "\\Temp\\p.ps1" or tgt.process.cmdline contains "\\Temp\\1.ps1" or tgt.process.cmdline contains "Hound.ps1" or tgt.process.cmdline contains "encode.ps1" or tgt.process.cmdline contains "powercat.ps1")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Program Names
id: efdd8dd5-cee8-4e59-9390-7d4d5e4dd6f6
status: test
description: Detects suspicious patterns in program names or folders that are often found in malicious samples or hacktools
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
author: Florian Roth (Nextron Systems)
date: 2022-02-11
modified: 2023-03-22
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        - Image|contains:
              - '\CVE-202' # Update this when we reach the year 2100
              - '\CVE202' # Update this when we reach the year 2100
        - Image|endswith:
              - '\poc.exe'
              - '\artifact.exe'
              - '\artifact64.exe'
              - '\artifact_protected.exe'
              - '\artifact32.exe'
              - '\artifact32big.exe'
              - 'obfuscated.exe'
              - 'obfusc.exe'
              - '\meterpreter'
    selection_commandline:
        CommandLine|contains:
            - 'inject.ps1'
            - 'Invoke-CVE'
            - 'pupy.ps1'
            - 'payload.ps1'
            - 'beacon.ps1'
            - 'PowerView.ps1'
            - 'bypass.ps1'
            - 'obfuscated.ps1'
            - 'obfusc.ps1'
            - 'obfus.ps1'
            - 'obfs.ps1'
            - 'evil.ps1'
            - 'MiniDogz.ps1'
            - '_enc.ps1'
            - '\shell.ps1'
            - '\rshell.ps1'
            - 'revshell.ps1'
            - '\av.ps1'
            - '\av_test.ps1'
            - 'adrecon.ps1'
            - 'mimikatz.ps1'
            - '\PowerUp_'
            - 'powerup.ps1'
            - '\Temp\a.ps1'
            - '\Temp\p.ps1'
            - '\Temp\1.ps1'
            - 'Hound.ps1'
            - 'encode.ps1'
            - 'powercat.ps1'
    condition: 1 of selection*
falsepositives:
    - Legitimate tools that accidentally match on the searched patterns
level: high
```
