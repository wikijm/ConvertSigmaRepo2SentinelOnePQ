```sql
// Translated content (automatically translated on 12-07-2025 01:24:44):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\vss_ps.dll" and (not ((src.process.image.path contains "C:\Windows\" and (src.process.image.path contains "\clussvc.exe" or src.process.image.path contains "\dismhost.exe" or src.process.image.path contains "\dllhost.exe" or src.process.image.path contains "\inetsrv\appcmd.exe" or src.process.image.path contains "\inetsrv\iissetup.exe" or src.process.image.path contains "\msiexec.exe" or src.process.image.path contains "\rundll32.exe" or src.process.image.path contains "\searchindexer.exe" or src.process.image.path contains "\srtasks.exe" or src.process.image.path contains "\svchost.exe" or src.process.image.path contains "\System32\SystemPropertiesAdvanced.exe" or src.process.image.path contains "\taskhostw.exe" or src.process.image.path contains "\thor.exe" or src.process.image.path contains "\thor64.exe" or src.process.image.path contains "\tiworker.exe" or src.process.image.path contains "\vssvc.exe" or src.process.image.path contains "\WmiPrvSE.exe" or src.process.image.path contains "\wsmprovhost.exe")) or (src.process.image.path contains "C:\Program Files\" or src.process.image.path contains "C:\Program Files (x86)\") or (src.process.cmdline contains "C:\$WinREAgent\Scratch\" and src.process.cmdline contains "\dismhost.exe {") or not (src.process.image.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Volume Shadow Copy VSS_PS.dll Load
id: 333cdbe8-27bb-4246-bf82-b41a0dca4b70
related:
    - id: 48bfd177-7cf2-412b-ad77-baf923489e82 # vsstrace.dll
      type: similar
    - id: 37774c23-25a1-4adb-bb6d-8bb9fd59c0f8 # vssapi.dll
      type: similar
status: test
description: Detects the image load of vss_ps.dll by uncommon executables
references:
    - https://www.virustotal.com/gui/file/ba88ca45589fae0139a40ca27738a8fc2dfbe1be5a64a9558f4e0f52b35c5add
    - https://twitter.com/am0nsec/status/1412232114980982787
author: Markus Neis, @markus_neis
date: 2021-07-07
modified: 2024-03-28
tags:
    - attack.defense-evasion
    - attack.impact
    - attack.t1490
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\vss_ps.dll'
    filter_legit:
        Image|startswith: 'C:\Windows\'
        Image|endswith:
            - '\clussvc.exe'
            - '\dismhost.exe'
            - '\dllhost.exe'
            - '\inetsrv\appcmd.exe'
            - '\inetsrv\iissetup.exe'
            - '\msiexec.exe'
            - '\rundll32.exe'
            - '\searchindexer.exe'
            - '\srtasks.exe'
            - '\svchost.exe'
            - '\System32\SystemPropertiesAdvanced.exe'
            - '\taskhostw.exe'
            - '\thor.exe'
            - '\thor64.exe'
            - '\tiworker.exe'
            - '\vssvc.exe'
            - '\WmiPrvSE.exe'
            - '\wsmprovhost.exe'
    filter_programfiles:
        # When using this rule in your environment replace the "Program Files" folder by the exact applications you know use this. Examples would be software such as backup solutions
        Image|startswith:
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    filter_update:
        CommandLine|startswith: 'C:\$WinREAgent\Scratch\'
        CommandLine|contains: '\dismhost.exe {'
    filter_image_null:
        Image: null
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: high
```
