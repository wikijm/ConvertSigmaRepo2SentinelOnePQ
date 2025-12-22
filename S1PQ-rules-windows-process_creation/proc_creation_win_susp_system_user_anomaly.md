```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((((tgt.process.integrityLevel in ("System","S-1-16-16384")) and (tgt.process.user contains "AUTHORI" or tgt.process.user contains "AUTORI")) and ((tgt.process.image.path contains "\\calc.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\forfiles.exe" or tgt.process.image.path contains "\\hh.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\ping.exe" or tgt.process.image.path contains "\\wscript.exe") or tgt.process.cmdline matches "net\\s+user\\s+" or (tgt.process.cmdline contains " -NoP " or tgt.process.cmdline contains " -W Hidden " or tgt.process.cmdline contains " -decode " or tgt.process.cmdline contains " /decode " or tgt.process.cmdline contains " /urlcache " or tgt.process.cmdline contains " -urlcache " or tgt.process.cmdline="* -e* JAB*" or tgt.process.cmdline="* -e* SUVYI*" or tgt.process.cmdline="* -e* SQBFAFgA*" or tgt.process.cmdline="* -e* aWV4I*" or tgt.process.cmdline="* -e* IAB*" or tgt.process.cmdline="* -e* PAA*" or tgt.process.cmdline="* -e* aQBlAHgA*" or tgt.process.cmdline contains "vssadmin delete shadows" or tgt.process.cmdline contains "reg SAVE HKLM" or tgt.process.cmdline contains " -ma " or tgt.process.cmdline contains "Microsoft\\Windows\\CurrentVersion\\Run" or tgt.process.cmdline contains ".downloadstring(" or tgt.process.cmdline contains ".downloadfile(" or tgt.process.cmdline contains " /ticket:" or tgt.process.cmdline contains "dpapi::" or tgt.process.cmdline contains "event::clear" or tgt.process.cmdline contains "event::drop" or tgt.process.cmdline contains "id::modify" or tgt.process.cmdline contains "kerberos::" or tgt.process.cmdline contains "lsadump::" or tgt.process.cmdline contains "misc::" or tgt.process.cmdline contains "privilege::" or tgt.process.cmdline contains "rpc::" or tgt.process.cmdline contains "sekurlsa::" or tgt.process.cmdline contains "sid::" or tgt.process.cmdline contains "token::" or tgt.process.cmdline contains "vault::cred" or tgt.process.cmdline contains "vault::list" or tgt.process.cmdline contains " p::d " or tgt.process.cmdline contains ";iex(" or tgt.process.cmdline contains "MiniDump"))) and (not ((tgt.process.cmdline contains "ping" and tgt.process.cmdline contains "127.0.0.1" and tgt.process.cmdline contains " -n ") or (tgt.process.image.path contains "\\PING.EXE" and src.process.cmdline contains "\\DismFoDInstall.cmd") or src.process.image.path contains ":\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\" or ((src.process.image.path contains ":\\Program Files (x86)\\Java\\" or src.process.image.path contains ":\\Program Files\\Java\\") and src.process.image.path contains "\\bin\\javaws.exe" and (tgt.process.image.path contains ":\\Program Files (x86)\\Java\\" or tgt.process.image.path contains ":\\Program Files\\Java\\") and tgt.process.image.path contains "\\bin\\jp2launcher.exe" and tgt.process.cmdline contains " -ma ")))))
```


# Original Sigma Rule:
```yaml
title: Suspicious SYSTEM User Process Creation
id: 2617e7ed-adb7-40ba-b0f3-8f9945fe6c09
status: test
description: Detects a suspicious process creation as SYSTEM user (suspicious program or command line parameter)
references:
    - Internal Research
    - https://tools.thehacker.recipes/mimikatz/modules
author: Florian Roth (Nextron Systems), David ANDRE (additional keywords)
date: 2021-12-20
modified: 2025-10-19
tags:
    - attack.credential-access
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1134
    - attack.t1003
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        IntegrityLevel:
            - 'System'
            - 'S-1-16-16384'
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    selection_special:
        - Image|endswith:
              - '\calc.exe'
              - '\cscript.exe'
              - '\forfiles.exe'
              - '\hh.exe'
              - '\mshta.exe'
              - '\ping.exe'
              - '\wscript.exe'
        - CommandLine|re: 'net\s+user\s+'
        - CommandLine|contains:
              # - 'sc stop ' # stops a system service # causes FPs
              - ' -NoP '  # Often used in malicious PowerShell commands
              - ' -W Hidden '  # Often used in malicious PowerShell commands
              - ' -decode '  # Used with certutil
              - ' /decode '  # Used with certutil
              - ' /urlcache '  # Used with certutil
              - ' -urlcache '  # Used with certutil
              - ' -e* JAB'  # PowerShell encoded commands
              - ' -e* SUVYI'  # PowerShell encoded commands
              - ' -e* SQBFAFgA'  # PowerShell encoded commands
              - ' -e* aWV4I'  # PowerShell encoded commands
              - ' -e* IAB'  # PowerShell encoded commands
              - ' -e* PAA'  # PowerShell encoded commands
              - ' -e* aQBlAHgA'  # PowerShell encoded commands
              - 'vssadmin delete shadows'  # Ransomware
              - 'reg SAVE HKLM'  # save registry SAM - syskey extraction
              - ' -ma '  # ProcDump
              - 'Microsoft\Windows\CurrentVersion\Run'  # Run key in command line - often in combination with REG ADD
              - '.downloadstring('  # PowerShell download command
              - '.downloadfile('  # PowerShell download command
              - ' /ticket:'  # Rubeus
              - 'dpapi::'     # Mimikatz
              - 'event::clear'        # Mimikatz
              - 'event::drop'     # Mimikatz
              - 'id::modify'      # Mimikatz
              - 'kerberos::'       # Mimikatz
              - 'lsadump::'      # Mimikatz
              - 'misc::'     # Mimikatz
              - 'privilege::'       # Mimikatz
              - 'rpc::'      # Mimikatz
              - 'sekurlsa::'       # Mimikatz
              - 'sid::'        # Mimikatz
              - 'token::'      # Mimikatz
              - 'vault::cred'     # Mimikatz
              - 'vault::list'     # Mimikatz
              - ' p::d '  # Mimikatz
              - ';iex('  # PowerShell IEX
              - 'MiniDump'  # Process dumping method apart from procdump
    filter_main_ping:
        CommandLine|contains|all:
            - 'ping'
            - '127.0.0.1'
            - ' -n '
    filter_vs:
        Image|endswith: '\PING.EXE'
        ParentCommandLine|contains: '\DismFoDInstall.cmd'
    filter_config_mgr:
        ParentImage|contains: ':\Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows\'
    filter_java:
        ParentImage|contains:
            - ':\Program Files (x86)\Java\'
            - ':\Program Files\Java\'
        ParentImage|endswith: '\bin\javaws.exe'
        Image|contains:
            - ':\Program Files (x86)\Java\'
            - ':\Program Files\Java\'
        Image|endswith: '\bin\jp2launcher.exe'
        CommandLine|contains: ' -ma '
    condition: all of selection* and not 1 of filter_*
falsepositives:
    - Administrative activity
    - Scripts and administrative tools used in the monitored environment
    - Monitoring activity
level: high
```
