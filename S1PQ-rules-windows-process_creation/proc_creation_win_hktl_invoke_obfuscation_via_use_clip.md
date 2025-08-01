```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline matches "(?i)echo.*clip.*&&.*(Clipboard|i`?n`?v`?o`?k`?e`?)")
```


# Original Sigma Rule:
```yaml
title: Invoke-Obfuscation Via Use Clip
id: e1561947-b4e3-4a74-9bdd-83baed21bdb5
status: test
description: Detects Obfuscated Powershell via use Clip.exe in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task29)
author: Nikita Nazarov, oscd.community
date: 2020-10-09
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
        # Example 1: C:\WINdoWS\sySteM32\CMd /c " ECho\Invoke-Expression (New-Object Net.WebClient).DownloadString|Clip.Exe&&C:\WINdoWS\sySteM32\CMd /c pOWerSheLl -STa . ( \"{2}{0}{1}\"-f'dd-',(\"{0}{1}\" -f 'T','ype' ),'A' ) -Assembly ( \"{4}{1}{3}{0}{2}\"-f (\"{0}{1}\" -f 'nd','ow'),( \"{1}{0}\"-f'.W','stem' ),( \"{2}{1}{0}\" -f 'rms','Fo','s.'),'i','Sy') ; ${exeCUtIOnCONTeXT}.\"INV`oKECOM`m`ANd\".\"INV`ok`ESCriPT\"( ( [sYSteM.wiNDoWS.forMs.ClIPboaRD]::( \"{2}{0}{1}\" -f'Ex','t',(\"{0}{1}\" -f'Get','t' ) ).\"iNvo`Ke\"( )) ) ; [System.Windows.Forms.Clipboard]::(\"{1}{0}\" -f 'ar','Cle' ).\"in`V`oKE\"( )"
        # Example 2: C:\WINDowS\sYsTEM32\CmD.eXE /C" echo\Invoke-Expression (New-Object Net.WebClient).DownloadString| C:\WIndOWs\SYSteM32\CLip &&C:\WINDowS\sYsTEM32\CmD.eXE /C POWERSHeLL -sT -noL [Void][System.Reflection.Assembly]::( \"{0}{3}{4}{1}{2}\" -f( \"{0}{1}\"-f'Lo','adW' ),( \"{0}{1}\"-f 'Par','t'),( \"{0}{1}{2}\"-f 'ial','N','ame'),'it','h' ).\"in`VO`KE\"( ( \"{3}{1}{4}{5}{2}{0}\"-f'rms','ystem.Windo','Fo','S','w','s.' )) ; ( [wIndows.fOrms.cLIPBOArD]::( \"{1}{0}\"-f'T',( \"{1}{0}\" -f'tEX','gET' )).\"i`Nvoke\"( ) ) ^^^| ^^^& ( ( ^^^& ( \"{2}{1}{0}\"-f 'e',( \"{2}{1}{0}\"-f'IABl','aR','v' ),( \"{0}{1}\"-f'Get','-' ) ) ( \"{1}{0}\"-f'*','*MDr' )).\"n`Ame\"[3,11,2]-jOin'') ; [Windows.Forms.Clipboard]::( \"{0}{1}\" -f (\"{1}{0}\"-f'tT','Se' ),'ext').\"in`VoKe\"(' ' )"
        CommandLine|re: '(?i)echo.*clip.*&&.*(Clipboard|i`?n`?v`?o`?k`?e`?)'
    condition: selection
falsepositives:
    - Unknown
level: high
```
