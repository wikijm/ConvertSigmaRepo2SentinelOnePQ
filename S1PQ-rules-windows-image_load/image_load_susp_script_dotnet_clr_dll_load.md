```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and ((src.process.image.path contains "\\cmstp.exe" or src.process.image.path contains "\\cscript.exe" or src.process.image.path contains "\\mshta.exe" or src.process.image.path contains "\\msxsl.exe" or src.process.image.path contains "\\regsvr32.exe" or src.process.image.path contains "\\wmic.exe" or src.process.image.path contains "\\wscript.exe") and (module.path contains "\\clr.dll" or module.path contains "\\mscoree.dll" or module.path contains "\\mscorlib.dll")))
```


# Original Sigma Rule:
```yaml
title: DotNet CLR DLL Loaded By Scripting Applications
id: 4508a70e-97ef-4300-b62b-ff27992990ea
status: test
description: Detects .NET CLR DLLs being loaded by scripting applications such as wscript or cscript. This could be an indication of potential suspicious execution.
references:
    - https://github.com/tyranid/DotNetToJScript
    - https://thewover.github.io/Introducing-Donut/
    - https://web.archive.org/web/20230329154538/https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html
    - https://web.archive.org/web/20221026202428/https://gist.github.com/code-scrap/d7f152ffcdb3e0b02f7f394f5187f008
author: omkar72, oscd.community
date: 2020-10-14
modified: 2023-02-23
tags:
    - attack.defense-evasion
    - attack.execution
    - attack.privilege-escalation
    - attack.t1055
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith:
            - '\cmstp.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\msxsl.exe'
            - '\regsvr32.exe'
            # - '\svchost.exe'
            - '\wmic.exe'
            - '\wscript.exe'
        ImageLoaded|endswith:
            - '\clr.dll'
            - '\mscoree.dll'
            - '\mscorlib.dll'
    condition: selection
falsepositives:
    - Unknown
level: high
```
