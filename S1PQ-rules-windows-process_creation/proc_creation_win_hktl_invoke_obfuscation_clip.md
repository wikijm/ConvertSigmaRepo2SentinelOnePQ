```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "cmd" and tgt.process.cmdline contains "&&" and tgt.process.cmdline contains "clipboard]::" and tgt.process.cmdline contains "-f") and (tgt.process.cmdline contains "/c" or tgt.process.cmdline contains "/r")))
```


# Original Sigma Rule:
```yaml
title: Invoke-Obfuscation CLIP+ Launcher
id: b222df08-0e07-11eb-adc1-0242ac120002
status: test
description: Detects Obfuscated use of Clip.exe to execute PowerShell
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task 26)
author: Jonathan Cheong, oscd.community
date: 2020-10-13
modified: 2022-11-17
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
        # CommandLine|re: 'cmd.{0,5}(?:\/c|\/r).+clip(?:\.exe)?.{0,4}&&.+clipboard]::\(\s\\\"\{\d\}.+\-f.+\"'
        # Example 1: Cmd /c" echo/Invoke-Expression (New-Object Net.WebClient).DownloadString |cLiP&& POWerSheLl -Nolog -sT . (\"{1}{2}{0}\"-f'pe','Ad',(\"{1}{0}\" -f'Ty','d-' ) ) -Assemb ( \"{5}{1}{3}{0}{2}{4}\" -f'ows','y','.F',(\"{0}{1}{2}\" -f'stem.W','i','nd'),( \"{0}{1}\"-f 'o','rms' ),'S' ) ; ([SySTEM.wiNDows.FoRmS.CLiPbOArd]::( \"{1}{0}\" -f (\"{1}{0}\" -f'T','TTeX' ),'gE' ).\"invO`Ke\"( ) ) ^| ^&( \"{5}{1}{2}{4}{3}{0}\" -f 'n',( \"{1}{0}\"-f'KE-','o' ),(\"{2}{1}{0}\"-f 'pRESS','x','e' ),'o','i','iNV') ; [System.Windows.Forms.Clipboard]::(\"{0}{1}\" -f( \"{1}{0}\"-f'e','SetT' ),'xt').\"InV`oKe\"( ' ')"
        # Example 2: CMD/c " ECho Invoke-Expression (New-Object Net.WebClient).DownloadString|c:\WiNDowS\SySteM32\cLip && powershElL -noPRO -sTa ^& (\"{2}{0}{1}\" -f 'dd',(\"{1}{0}\"-f 'ype','-T' ),'A' ) -AssemblyN (\"{0}{3}{2}{1}{4}\"-f'Pr','nCo',(\"{0}{1}\"-f'e','ntatio'),'es','re' ) ; ^& ( ( [StRinG]${ve`RB`OSE`pr`e`FeReNCE} )[1,3] + 'x'-JoiN'') ( ( [sySTem.WInDOWs.ClipbOaRD]::( \"{1}{0}\" -f(\"{0}{1}\" -f'tTe','xt' ),'ge' ).\"IN`Vo`Ke\"( ) ) ) ; [System.Windows.Clipboard]::( \"{2}{1}{0}\" -f't',( \"{0}{1}\" -f 'tT','ex' ),'Se' ).\"In`V`oKe\"( ' ' )"
        CommandLine|contains|all:
            - 'cmd'
            - '&&'
            - 'clipboard]::'
            - '-f'
        CommandLine|contains:
            - '/c'
            - '/r'
    condition: selection
falsepositives:
    - Unknown
level: high
```
