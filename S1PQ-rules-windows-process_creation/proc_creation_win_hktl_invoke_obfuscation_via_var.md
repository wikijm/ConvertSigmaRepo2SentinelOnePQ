```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "&&set" and tgt.process.cmdline contains "cmd" and tgt.process.cmdline contains "/c" and tgt.process.cmdline contains "-f") and (tgt.process.cmdline contains "{0}" or tgt.process.cmdline contains "{1}" or tgt.process.cmdline contains "{2}" or tgt.process.cmdline contains "{3}" or tgt.process.cmdline contains "{4}" or tgt.process.cmdline contains "{5}")))
```


# Original Sigma Rule:
```yaml
title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION
id: e9f55347-2928-4c06-88e5-1a7f8169942e
status: test
description: Detects Obfuscated Powershell via VAR++ LAUNCHER
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task27)
author: Timur Zinniatullin, oscd.community
date: 2020-10-13
modified: 2022-11-16
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
        # CommandLine|re: '(?i)&&set.*(\{\d\}){2,}\\\"\s+?\-f.*&&.*cmd.*\/c' # FPs with |\/r
        # Example 1: CMD /C"sET KUR=Invoke-Expression (New-Object Net.WebClient).DownloadString&&Set MxI=C:\wINDowS\sYsWow64\winDOWspoWERSheLl\V1.0\PowerShelL.EXe ${ExEcut`IoN`cON`TExT}.\"invo`kEcoMm`A`ND\".( \"{2}{1}{0}\" -f 'pt','EscRi','INvOk' ).Invoke( ( .( \"{0}{1}\" -f'D','IR' ) ( \"{0}{1}\"-f'ENV:kU','R')).\"vAl`Ue\" )&& CMD /C%mXI%"
        # Example 2: c:\WiNDOWS\sYSTEm32\CmD.exE /C "sEt DeJLz=Invoke-Expression (New-Object Net.WebClient).DownloadString&&set yBKM=PoWERShelL -noeX ^^^&(\"{2}{0}{1}\"-f '-ItE','m','seT') ( 'V' + 'a'+ 'RiAblE:z8J' +'U2' + 'l' ) ([TYpE]( \"{2}{3}{0}{1}\"-f 'e','NT','e','NViRONM' ) ) ; ^^^& ( ( [sTrIng]${VE`Rbo`SepReFER`Ence})[1,3] + 'X'-joIN'')( ( (.('gI') ('V' + 'a' + 'RIAbLe:z8j' + 'u2' +'l' ) ).vALUe::( \"{2}{5}{0}{1}{6}{4}{3}\" -f 'IRo','Nm','GETE','ABlE','I','nv','enTVAr').Invoke(( \"{0}{1}\"-f'd','ejLz' ),( \"{1}{2}{0}\"-f'cEss','P','RO') )) )&& c:\WiNDOWS\sYSTEm32\CmD.exE /C %ybkm%"
        CommandLine|contains|all:
            - '&&set'
            - 'cmd'
            - '/c'
            - '-f'
        CommandLine|contains:
            - '{0}'
            - '{1}'
            - '{2}'
            - '{3}'
            - '{4}'
            - '{5}'
    condition: selection
falsepositives:
    - Unknown
level: high
```
