```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((((tgt.process.image.path contains "\NTDSDump.exe" or tgt.process.image.path contains "\NTDSDumpEx.exe") or (tgt.process.cmdline contains "ntds.dit" and tgt.process.cmdline contains "system.hiv") or tgt.process.cmdline contains "NTDSgrab.ps1") or (tgt.process.cmdline contains "ac i ntds" and tgt.process.cmdline contains "create full") or (tgt.process.cmdline contains "/c copy " and tgt.process.cmdline contains "\windows\ntds\ntds.dit") or (tgt.process.cmdline contains "activate instance ntds" and tgt.process.cmdline contains "create full") or (tgt.process.cmdline contains "powershell" and tgt.process.cmdline contains "ntds.dit")) or (tgt.process.cmdline contains "ntds.dit" and ((src.process.image.path contains "\apache" or src.process.image.path contains "\tomcat" or src.process.image.path contains "\AppData\" or src.process.image.path contains "\Temp\" or src.process.image.path contains "\Public\" or src.process.image.path contains "\PerfLogs\") or (tgt.process.image.path contains "\apache" or tgt.process.image.path contains "\tomcat" or tgt.process.image.path contains "\AppData\" or tgt.process.image.path contains "\Temp\" or tgt.process.image.path contains "\Public\" or tgt.process.image.path contains "\PerfLogs\")))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Process Patterns NTDS.DIT Exfil
id: 8bc64091-6875-4881-aaf9-7bd25b5dda08
status: test
description: Detects suspicious process patterns used in NTDS.DIT exfiltration
references:
    - https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
    - https://www.n00py.io/2022/03/manipulating-user-passwords-without-mimikatz/
    - https://pentestlab.blog/tag/ntds-dit/
    - https://github.com/samratashok/nishang/blob/414ee1104526d7057f9adaeee196d91ae447283e/Gather/Copy-VSS.ps1
    - https://github.com/zcgonvh/NTDSDumpEx
    - https://github.com/rapid7/metasploit-framework/blob/d297adcebb5c1df6fe30b12ca79b161deb71571c/data/post/powershell/NTDSgrab.ps1
    - https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html?m=1
author: Florian Roth (Nextron Systems)
date: 2022-03-11
modified: 2022-11-10
tags:
    - attack.credential-access
    - attack.t1003.003
logsource:
    product: windows
    category: process_creation
detection:
    selection_tool:
        # https://github.com/zcgonvh/NTDSDumpEx
        - Image|endswith:
              - '\NTDSDump.exe'
              - '\NTDSDumpEx.exe'
        - CommandLine|contains|all:
              # ntdsdumpex.exe -d ntds.dit -o hash.txt -s system.hiv
              - 'ntds.dit'
              - 'system.hiv'
        - CommandLine|contains: 'NTDSgrab.ps1'
    selection_oneliner_1:
        # powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
        CommandLine|contains|all:
            - 'ac i ntds'
            - 'create full'
    selection_onliner_2:
        # cmd.exe /c copy z:\windows\ntds\ntds.dit c:\exfil\ntds.dit
        CommandLine|contains|all:
            - '/c copy '
            - '\windows\ntds\ntds.dit'
    selection_onliner_3:
        # ntdsutil "activate instance ntds" "ifm" "create full c:\windows\temp\data\" "quit" "quit"
        CommandLine|contains|all:
            - 'activate instance ntds'
            - 'create full'
    selection_powershell:
        CommandLine|contains|all:
            - 'powershell'
            - 'ntds.dit'
    set1_selection_ntds_dit:
        CommandLine|contains: 'ntds.dit'
    set1_selection_image_folder:
        - ParentImage|contains:
              - '\apache'
              - '\tomcat'
              - '\AppData\'
              - '\Temp\'
              - '\Public\'
              - '\PerfLogs\'
        - Image|contains:
              - '\apache'
              - '\tomcat'
              - '\AppData\'
              - '\Temp\'
              - '\Public\'
              - '\PerfLogs\'
    condition: 1 of selection* or all of set1*
falsepositives:
    - Unknown
level: high
```
