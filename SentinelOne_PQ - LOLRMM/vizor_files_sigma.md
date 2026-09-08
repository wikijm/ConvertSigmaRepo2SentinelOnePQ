```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\CLBOOT32.EXE" or tgt.file.path contains "C:\\Program Files\\Vector\\Asset Management Client\\CLBOOT32.EXE" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\CLDIST32.EXE" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\CLDISTSVC.EXE" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\clMeter32.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\clMeterSvc.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\HTTPGet.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\HTTPPush.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\WINCHK32.EXE" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\regapps.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\lutinfow32.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\LuSMBIOS32.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\LuLogon.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\LUGuard.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\LUEDIT.EXE" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\SelfUpdater.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\VnlSelfUpdate.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\VNLDriverInstaller.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\PidUpdater.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\cpuchk.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\upload.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\NUKE32.EXE" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\Recycler.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\closeapp.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\VECWAIT.EXE" or tgt.file.path contains "C:\\Program Files (x86)\\Vector\\Asset Management Client\\Prep64.exe" or tgt.file.path contains "C:\\Program Files\\Vector Networks Limited\\LANutil32 Suite\\clboot32.exe" or tgt.file.path contains "C:\\luhboot.bat" or tgt.file.path contains "C:\\winchk.dat" or tgt.file.path contains "C:\\LUCLIENT.INI" or tgt.file.path contains "C:\\LUCLIENT.MOD"))
```


# Original Sigma Rule:
```yaml
title: Potential VIZOR RMM Tool File Activity
id: 8ff1651e-d82d-5df2-b101-5534c69d9bba
status: experimental
description: |
    Detects potential files activity of VIZOR RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files (x86)\Vector\Asset Management Client\CLBOOT32.EXE'
            - 'C:\Program Files\Vector\Asset Management Client\CLBOOT32.EXE'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\CLDIST32.EXE'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\CLDISTSVC.EXE'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\clMeter32.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\clMeterSvc.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\HTTPGet.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\HTTPPush.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\WINCHK32.EXE'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\regapps.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\lutinfow32.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\LuSMBIOS32.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\LuLogon.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\LUGuard.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\LUEDIT.EXE'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\SelfUpdater.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\VnlSelfUpdate.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\VNLDriverInstaller.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\PidUpdater.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\cpuchk.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\upload.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\NUKE32.EXE'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\Recycler.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\closeapp.exe'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\VECWAIT.EXE'
            - 'C:\Program Files (x86)\Vector\Asset Management Client\Prep64.exe'
            - 'C:\Program Files\Vector Networks Limited\LANutil32 Suite\clboot32.exe'
            - 'C:\luhboot.bat'
            - 'C:\winchk.dat'
            - 'C:\LUCLIENT.INI'
            - 'C:\LUCLIENT.MOD'
    condition: selection
falsepositives:
    - Legitimate use of VIZOR
level: medium
```
