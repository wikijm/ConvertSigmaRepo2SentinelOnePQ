```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline matches "cmd.{0,5}(?:/c|/r)(?:\\s|)\\"set\\s[a-zA-Z]{3,6}.*(?:\\{\\d\\}){1,}\\\\\\"\\s+?\\-f(?:.*\\)){1,}.*\\"")
```


# Original Sigma Rule:
```yaml
title: Invoke-Obfuscation VAR+ Launcher
id: 27aec9c9-dbb0-4939-8422-1742242471d0
status: test
description: Detects Obfuscated use of Environment Variables to execute PowerShell
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task 24)
author: Jonathan Cheong, oscd.community
date: 2020-10-15
modified: 2024-04-15
tags:
    - attack.defense-evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Example 1: C:\winDoWs\SySTeM32\cmd.Exe /C"SET NOtI=Invoke-Expression (New-Object Net.WebClient).DownloadString&& PowERshElL -NOl SET-iteM ( 'VAR' + 'i'+ 'A' + 'blE:Ao6' + 'I0') ( [TYpe](\"{2}{3}{0}{1}\"-F 'iRoN','mENT','e','nv') ) ; ${exECUtIONCOnTEXT}.\"IN`VO`KecOmMaND\".\"inVo`KES`crIPt\"( ( ( GEt-VAriAble ( 'a' + 'o6I0') -vaLU )::(\"{1}{4}{2}{3}{0}\" -f'e','gETenvIR','NtvaRIa','BL','ONme' ).Invoke(( \"{0}{1}\"-f'n','oti' ),( \"{0}{1}\" -f'pRoC','esS') )) )"
        # Example 2: cMD.exe /C "seT SlDb=Invoke-Expression (New-Object Net.WebClient).DownloadString&& pOWErShell .(( ^&(\"{1}{0}{2}{3}\" -f 'eT-vaR','G','iab','lE' ) (\"{0}{1}\" -f '*m','DR*' ) ).\"na`ME\"[3,11,2]-JOIN'' ) ( ( ^&(\"{0}{1}\" -f'g','CI' ) (\"{0}{1}\" -f 'ENV',':SlDb' ) ).\"VA`luE\" ) "
        CommandLine|re: 'cmd.{0,5}(?:/c|/r)(?:\s|)\"set\s[a-zA-Z]{3,6}.*(?:\{\d\}){1,}\\\"\s+?\-f(?:.*\)){1,}.*\"'
    condition: selection
falsepositives:
    - Unknown
level: high
```
