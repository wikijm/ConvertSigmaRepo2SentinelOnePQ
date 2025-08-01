```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\vssapi.dll" and (not (((src.process.image.path in ("C:\Windows\explorer.exe","C:\Windows\ImmersiveControlPanel\SystemSettings.exe")) or (src.process.image.path contains "C:\Windows\System32\" or src.process.image.path contains "C:\Windows\SysWOW64\" or src.process.image.path contains "C:\Windows\Temp\{" or src.process.image.path contains "C:\Windows\WinSxS\")) or (src.process.image.path contains "C:\Program Files\" or src.process.image.path contains "C:\Program Files (x86)\") or src.process.image.path contains "C:\ProgramData\Package Cache\"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Volume Shadow Copy Vssapi.dll Load
id: 37774c23-25a1-4adb-bb6d-8bb9fd59c0f8
related:
    - id: 333cdbe8-27bb-4246-bf82-b41a0dca4b70 # vss_ps.dll
      type: similar
    - id: 48bfd177-7cf2-412b-ad77-baf923489e82 # vsstrace.dll
      type: similar
status: test
description: Detects the image load of VSS DLL by uncommon executables
references:
    - https://github.com/ORCx41/DeleteShadowCopies
author: frack113
date: 2022-10-31
modified: 2023-05-03
tags:
    - attack.defense-evasion
    - attack.impact
    - attack.t1490
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\vssapi.dll'
    filter_windows:
        - Image:
              - 'C:\Windows\explorer.exe'
              - 'C:\Windows\ImmersiveControlPanel\SystemSettings.exe'
        - Image|startswith:
              - 'C:\Windows\System32\'
              - 'C:\Windows\SysWOW64\'
              - 'C:\Windows\Temp\{' # Installers
              - 'C:\Windows\WinSxS\'
    filter_program_files:
        # When using this rule in your environment replace the "Program Files" folder by the exact applications you know use this. Examples would be software such as backup solutions
        Image|startswith:
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    filter_programdata_packagecache:
        # The following filter is required because of many FPs cause by:
        #   C:\ProgramData\Package Cache\{10c6cfdc-27af-43fe-bbd3-bd20aae88451}\dotnet-sdk-3.1.425-win-x64.exe
        #   C:\ProgramData\Package Cache\{b9cfa33e-ace4-49f4-8bb4-82ded940990a}\windowsdesktop-runtime-6.0.11-win-x86.exe
        #   C:\ProgramData\Package Cache\{50264ff2-ad47-4569-abc4-1c350f285fb9}\aspnetcore-runtime-6.0.11-win-x86.exe
        #   C:\ProgramData\Package Cache\{2dcef8c3-1563-4149-a6ec-5b6c98500d7d}\dotnet-sdk-6.0.306-win-x64.exe
        #   etc.
        Image|startswith: 'C:\ProgramData\Package Cache\'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: high
```
