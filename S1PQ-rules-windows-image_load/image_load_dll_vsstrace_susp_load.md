```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\vsstrace.dll" and (not (((src.process.image.path in ("C:\Windows\explorer.exe","C:\Windows\ImmersiveControlPanel\SystemSettings.exe")) or (src.process.image.path contains "C:\Windows\System32\" or src.process.image.path contains "C:\Windows\SysWOW64\" or src.process.image.path contains "C:\Windows\Temp\{" or src.process.image.path contains "C:\Windows\WinSxS\" or src.process.image.path contains "C:\ProgramData\Package Cache\{")) or (src.process.image.path contains "C:\Program Files\" or src.process.image.path contains "C:\Program Files (x86)\")))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Volume Shadow Copy Vsstrace.dll Load
id: 48bfd177-7cf2-412b-ad77-baf923489e82
related:
    - id: 333cdbe8-27bb-4246-bf82-b41a0dca4b70 # vss_ps.dll
      type: similar
    - id: 37774c23-25a1-4adb-bb6d-8bb9fd59c0f8 # vssapi.dll
      type: similar
status: test
description: Detects the image load of VSS DLL by uncommon executables
references:
    - https://github.com/ORCx41/DeleteShadowCopies
author: frack113
date: 2023-02-17
modified: 2025-01-19
tags:
    - attack.defense-evasion
    - attack.impact
    - attack.t1490
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\vsstrace.dll'
    filter_main_windows:
        - Image:
              - 'C:\Windows\explorer.exe'
              - 'C:\Windows\ImmersiveControlPanel\SystemSettings.exe'
        - Image|startswith:
              - 'C:\Windows\System32\'
              - 'C:\Windows\SysWOW64\'
              - 'C:\Windows\Temp\{' # Installers
              - 'C:\Windows\WinSxS\'
              - 'C:\ProgramData\Package Cache\{'  # Microsoft Visual Redistributable installer  VC_redist/vcredist EXE
    filter_optional_program_files:
        # When using this rule in your environment replace the "Program Files" folder by the exact applications you know use this. Examples would be software such as backup solutions
        Image|startswith:
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: medium
```
