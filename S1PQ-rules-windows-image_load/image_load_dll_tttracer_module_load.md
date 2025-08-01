```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\ttdrecord.dll" or module.path contains "\ttdwriter.dll" or module.path contains "\ttdloader.dll"))
```


# Original Sigma Rule:
```yaml
title: Time Travel Debugging Utility Usage - Image
id: e76c8240-d68f-4773-8880-5c6f63595aaf
status: test
description: Detects usage of Time Travel Debugging Utility. Adversaries can execute malicious processes and dump processes, such as lsass.exe, via tttracer.exe.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Tttracer/
    - https://twitter.com/mattifestation/status/1196390321783025666
    - https://twitter.com/oulusoyum/status/1191329746069655553
author: 'Ensar Şamil, @sblmsrsn, @oscd_initiative'
date: 2020-10-06
modified: 2022-12-02
tags:
    - attack.defense-evasion
    - attack.credential-access
    - attack.t1218
    - attack.t1003.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded|endswith:
            - '\ttdrecord.dll'
            - '\ttdwriter.dll'
            - '\ttdloader.dll'
    condition: selection
falsepositives:
    - Legitimate usage by software developers/testers
level: high
```
