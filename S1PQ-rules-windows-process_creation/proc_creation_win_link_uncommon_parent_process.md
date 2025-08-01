```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\link.exe" and tgt.process.cmdline contains "LINK /") and (not ((src.process.image.path contains "C:\Program Files\Microsoft Visual Studio\" or src.process.image.path contains "C:\Program Files (x86)\Microsoft Visual Studio\") and (src.process.image.path contains "\VC\bin\" or src.process.image.path contains "\VC\Tools\")))))
```


# Original Sigma Rule:
```yaml
title: Uncommon Link.EXE Parent Process
id: 6e968eb1-5f05-4dac-94e9-fd0c5cb49fd6
status: test
description: |
    Detects an uncommon parent process of "LINK.EXE".
    Link.EXE in Microsoft incremental linker. Its a utility usually bundled with Visual Studio installation.
    Multiple utilities often found in the same folder (editbin.exe, dumpbin.exe, lib.exe, etc) have a hardcode call to the "LINK.EXE" binary without checking its validity.
    This would allow an attacker to sideload any binary with the name "link.exe" if one of the aforementioned tools get executed from a different location.
    By filtering the known locations of such utilities we can spot uncommon parent process of LINK.EXE that might be suspicious or malicious.
references:
    - https://twitter.com/0gtweet/status/1560732860935729152
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-22
modified: 2024-06-27
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\link.exe'
        CommandLine|contains: 'LINK /' # Hardcoded command line when we call tools like dumpbin.exe, editbin.exe, lib.exe...etc
    # Add other filters for other legitimate locations
    filter_main_visual_studio:
        ParentImage|startswith:
            - 'C:\Program Files\Microsoft Visual Studio\'
            - 'C:\Program Files (x86)\Microsoft Visual Studio\'
        ParentImage|contains:
            - '\VC\bin\'
            - '\VC\Tools\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
