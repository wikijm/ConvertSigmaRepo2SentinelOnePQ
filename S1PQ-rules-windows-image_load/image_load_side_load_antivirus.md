```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and ((module.path contains "\log.dll" and (not ((module.path contains "C:\Program Files\Bitdefender Antivirus Free\" or module.path contains "C:\Program Files (x86)\Bitdefender Antivirus Free\") or (src.process.image.path="C:\Program Files\Dell\SARemediation\audit\TelemetryUtility.exe" and (module.path in ("C:\Program Files\Dell\SARemediation\plugin\log.dll","C:\Program Files\Dell\SARemediation\audit\log.dll"))) or module.path contains "C:\Program Files\Canon\MyPrinter\"))) or (module.path contains "\qrt.dll" and (not (module.path contains "C:\Program Files\F-Secure\Anti-Virus\" or module.path contains "C:\Program Files (x86)\F-Secure\Anti-Virus\"))) or ((module.path contains "\ashldres.dll" or module.path contains "\lockdown.dll" or module.path contains "\vsodscpl.dll") and (not (module.path contains "C:\Program Files\McAfee\" or module.path contains "C:\Program Files (x86)\McAfee\"))) or (module.path contains "\vftrace.dll" and (not (module.path contains "C:\Program Files\CyberArk\Endpoint Privilege Manager\Agent\x32\" or module.path contains "C:\Program Files (x86)\CyberArk\Endpoint Privilege Manager\Agent\x32\"))) or (module.path contains "\wsc.dll" and (not (module.path contains "C:\program Files\AVAST Software\Avast\" or module.path contains "C:\program Files (x86)\AVAST Software\Avast\"))) or (module.path contains "\tmdbglog.dll" and (not (module.path contains "C:\program Files\Trend Micro\Titanium\" or module.path contains "C:\program Files (x86)\Trend Micro\Titanium\"))) or (module.path contains "\DLPPREM32.dll" and (not (module.path contains "C:\program Files\ESET" or module.path contains "C:\program Files (x86)\ESET")))))
```


# Original Sigma Rule:
```yaml
title: Potential Antivirus Software DLL Sideloading
id: 552b6b65-df37-4d3e-a258-f2fc4771ae54
status: test
description: Detects potential DLL sideloading of DLLs that are part of antivirus software suchas McAfee, Symantec...etc
references:
    - https://hijacklibs.net/ # For list of DLLs that could be sideloaded (search for dlls mentioned here in there)
author: Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
date: 2022-08-17
modified: 2023-03-13
tags:
    - attack.defense-evasion
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    # Bitdefender
    selection_bitdefender:
        ImageLoaded|endswith: '\log.dll'
    filter_log_dll_bitdefender:
        ImageLoaded|startswith:
            - 'C:\Program Files\Bitdefender Antivirus Free\'
            - 'C:\Program Files (x86)\Bitdefender Antivirus Free\'
    filter_log_dll_dell_sar:
        Image: 'C:\Program Files\Dell\SARemediation\audit\TelemetryUtility.exe'
        ImageLoaded:
            - 'C:\Program Files\Dell\SARemediation\plugin\log.dll'
            - 'C:\Program Files\Dell\SARemediation\audit\log.dll'
    filter_log_dll_canon:
        ImageLoaded|startswith: 'C:\Program Files\Canon\MyPrinter\'
    # F-Secure
    selection_fsecure:
        ImageLoaded|endswith: '\qrt.dll'
    filter_fsecure:
        ImageLoaded|startswith:
            - 'C:\Program Files\F-Secure\Anti-Virus\'
            - 'C:\Program Files (x86)\F-Secure\Anti-Virus\'
    # McAfee
    selection_mcafee:
        ImageLoaded|endswith:
            - '\ashldres.dll'
            - '\lockdown.dll'
            - '\vsodscpl.dll'
    filter_mcafee:
        ImageLoaded|startswith:
            - 'C:\Program Files\McAfee\'
            - 'C:\Program Files (x86)\McAfee\'
    # CyberArk
    selection_cyberark:
        ImageLoaded|endswith: '\vftrace.dll'
    filter_cyberark:
        ImageLoaded|startswith:
            - 'C:\Program Files\CyberArk\Endpoint Privilege Manager\Agent\x32\'
            - 'C:\Program Files (x86)\CyberArk\Endpoint Privilege Manager\Agent\x32\'
    # Avast
    selection_avast:
        ImageLoaded|endswith: '\wsc.dll'
    filter_avast:
        ImageLoaded|startswith:
            - 'C:\program Files\AVAST Software\Avast\'
            - 'C:\program Files (x86)\AVAST Software\Avast\'
    # ESET
    selection_eset_deslock:
        ImageLoaded|endswith: '\DLPPREM32.dll'
    filter_eset_deslock:
        ImageLoaded|startswith:
            - 'C:\program Files\ESET'
            - 'C:\program Files (x86)\ESET'
    # Trend Micro Titanium
    selection_titanium:
        ImageLoaded|endswith: '\tmdbglog.dll'
    filter_titanium:
        ImageLoaded|startswith:
            - 'C:\program Files\Trend Micro\Titanium\'
            - 'C:\program Files (x86)\Trend Micro\Titanium\'
    condition: (selection_bitdefender and not 1 of filter_log_dll_*)
               or (selection_fsecure and not filter_fsecure)
               or (selection_mcafee and not filter_mcafee)
               or (selection_cyberark and not filter_cyberark)
               or (selection_avast and not filter_avast)
               or (selection_titanium and not filter_titanium)
               or (selection_eset_deslock and not filter_eset_deslock)
falsepositives:
    - Applications that load the same dlls mentioned in the detection section. Investigate them and filter them out if a lot FPs are caused.
    - Dell SARemediation plugin folder (C:\Program Files\Dell\SARemediation\plugin\log.dll) is known to contain the 'log.dll' file.
    - The Canon MyPrinter folder 'C:\Program Files\Canon\MyPrinter\' is known to contain the 'log.dll' file
level: medium
```
