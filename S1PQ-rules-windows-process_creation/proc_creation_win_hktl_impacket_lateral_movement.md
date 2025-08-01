```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\wmiprvse.exe" or src.process.image.path contains "\mmc.exe" or src.process.image.path contains "\explorer.exe" or src.process.image.path contains "\services.exe") and (tgt.process.cmdline contains "cmd.exe" and tgt.process.cmdline contains "/Q" and tgt.process.cmdline contains "/c" and tgt.process.cmdline contains "\\127.0.0.1\" and tgt.process.cmdline contains "&1")) or ((src.process.cmdline contains "svchost.exe -k netsvcs" or src.process.cmdline contains "taskeng.exe") and (tgt.process.cmdline contains "cmd.exe" and tgt.process.cmdline contains "/C" and tgt.process.cmdline contains "Windows\Temp\" and tgt.process.cmdline contains "&1")))) | columns tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: HackTool - Potential Impacket Lateral Movement Activity
id: 10c14723-61c7-4c75-92ca-9af245723ad2
related:
    - id: e31f89f7-36fb-4697-8ab6-48823708353b
      type: obsolete
status: stable
description: Detects wmiexec/dcomexec/atexec/smbexec from Impacket framework
references:
    - https://github.com/SecureAuthCorp/impacket/blob/8b1a99f7c715702eafe3f24851817bb64721b156/examples/wmiexec.py
    - https://github.com/SecureAuthCorp/impacket/blob/8b1a99f7c715702eafe3f24851817bb64721b156/examples/atexec.py
    - https://github.com/SecureAuthCorp/impacket/blob/8b1a99f7c715702eafe3f24851817bb64721b156/examples/smbexec.py
    - https://github.com/SecureAuthCorp/impacket/blob/8b1a99f7c715702eafe3f24851817bb64721b156/examples/dcomexec.py
    - https://www.elastic.co/guide/en/security/current/suspicious-cmd-execution-via-wmi.html
author: Ecco, oscd.community, Jonhnathan Ribeiro, Tim Rauch
date: 2019-09-03
modified: 2023-02-21
tags:
    - attack.execution
    - attack.t1047
    - attack.lateral-movement
    - attack.t1021.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_other:
        # *** wmiexec.py
        #    parent is wmiprvse.exe
        #    examples:
        #       cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1567439113.54 2>&1
        #       cmd.exe /Q /c cd  1> \\127.0.0.1\ADMIN$\__1567439113.54 2>&1
        # *** dcomexec.py -object MMC20
        #   parent is mmc.exe
        #   example:
        #       "C:\Windows\System32\cmd.exe" /Q /c cd  1> \\127.0.0.1\ADMIN$\__1567442499.05 2>&1
        # *** dcomexec.py -object ShellBrowserWindow
        #  runs %SystemRoot%\System32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll {c08afd90-f2a1-11d1-8455-00a0c91f3880} but parent command is explorer.exe
        #  example:
        #   "C:\Windows\System32\cmd.exe" /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1567520103.71 2>&1
        # *** smbexec.py
        #   parent is services.exe
        #   example:
        #       C:\Windows\system32\cmd.exe /Q /c echo tasklist ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat
        ParentImage|endswith:
            - '\wmiprvse.exe'        # wmiexec
            - '\mmc.exe'        # dcomexec MMC
            - '\explorer.exe'        # dcomexec ShellBrowserWindow
            - '\services.exe'        # smbexec
        CommandLine|contains|all:
            - 'cmd.exe'
            - '/Q'
            - '/c'
            - '\\\\127.0.0.1\\'
            - '&1'
    selection_atexec:
        ParentCommandLine|contains:
            - 'svchost.exe -k netsvcs'       # atexec on win10 (parent is "C:\Windows\system32\svchost.exe -k netsvcs")
            - 'taskeng.exe'       # atexec on win7 (parent is "taskeng.exe {AFA79333-694C-4BEE-910E-E57D9A3518F6} S-1-5-18:NT AUTHORITY\System:Service:")
            # cmd.exe /C tasklist /m > C:\Windows\Temp\bAJrYQtL.tmp 2>&1
        CommandLine|contains|all:
            - 'cmd.exe'
            - '/C'
            - 'Windows\Temp\'
            - '&1'
    condition: 1 of selection_*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high
```
