```sql
// Translated content (automatically translated on 22-12-2025 00:55:34):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "\\AppData\\Roaming\\" or tgt.process.cmdline contains "\\AppData\\Local\\Temp\\") and (tgt.process.cmdline contains "\\{" and tgt.process.cmdline contains "}\\")) and (not ((tgt.process.image.path contains "\\{" and tgt.process.image.path contains "}\\") or not (tgt.process.image.path matches "\.*") or tgt.process.image.path="C:\\Windows\\System32\\drvinst.exe" or (tgt.process.image.path in ("C:\\Windows\\System32\\msiexec.exe","C:\\Windows\\SysWOW64\\msiexec.exe"))))))
```


# Original Sigma Rule:
```yaml
title: Potential Suspicious Execution From GUID Like Folder Names
id: 90b63c33-2b97-4631-a011-ceb0f47b77c3
status: test
description: |
    Detects potential suspicious execution of a GUID like folder name located in a suspicious location such as %TEMP% as seen being used in IcedID attacks.
    Use this rule to hunt for potentially suspicious activity stemming from uncommon folders.
references:
    - https://twitter.com/Kostastsale/status/1565257924204986369
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-01
modified: 2023-03-02
tags:
    - attack.defense-evasion
    - attack.t1027
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    # Uncomment this section and remove the filter if you want the rule to be more specific to processes
    # selection_img:
    #     Image|endswith:
    #         - '\rundll32.exe'
    selection_folder:
        CommandLine|contains:
            # Add more suspicious or unexpected paths
            - '\AppData\Roaming\'
            - '\AppData\Local\Temp\' # This could generate some FP with some installers creating folders with GUID
    selection_guid:
        CommandLine|contains|all:
            - '\{'
            - '}\'
    filter_main_image_guid:
        Image|contains|all:
            - '\{'
            - '}\'
    filter_main_null:
        Image: null
    filter_main_driver_inst:  # DrvInst.exe "4" "0" "C:\Users\venom\AppData\Local\Temp\{a0753cc2-fcea-4d49-a787-2290b564b06f}\nvvhci.inf" "9" "43a2fa8e7" "00000000000001C0" "WinSta0\Default" "00000000000001C4" "208" "c:\program files\nvidia corporation\installer2\nvvhci.{eb7b4460-7ec9-42d6-b73f-d487d4550526}"
        Image: 'C:\Windows\System32\drvinst.exe'
    filter_main_msiexec:
        Image:
            - 'C:\Windows\System32\msiexec.exe'
            - 'C:\Windows\SysWOW64\msiexec.exe'
    condition: all of selection_* and not 1 of filter*
falsepositives:
    - Installers are sometimes known for creating temporary folders with GUID like names. Add appropriate filters accordingly
level: low
```
