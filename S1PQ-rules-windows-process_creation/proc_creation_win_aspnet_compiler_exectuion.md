```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains ":\Windows\Microsoft.NET\Framework\" or tgt.process.image.path contains ":\Windows\Microsoft.NET\Framework64\" or tgt.process.image.path contains ":\Windows\Microsoft.NET\FrameworkArm\" or tgt.process.image.path contains ":\Windows\Microsoft.NET\FrameworkArm64\") and tgt.process.image.path contains "\aspnet_compiler.exe"))
```


# Original Sigma Rule:
```yaml
title: AspNetCompiler Execution
id: a01b8329-5953-4f73-ae2d-aa01e1f35f00 # Exec
related:
    - id: 9ccba514-7cb6-4c5c-b377-700758f2f120 # SuspChild
      type: similar
    - id: 4c7f49ee-2638-43bb-b85b-ce676c30b260 # TMP File
      type: similar
    - id: 9f50fe98-fe5c-4a2d-86c7-fad7f63ed622 # Susp Paths
      type: similar
status: test
description: Detects execution of "aspnet_compiler.exe" which can be abused to compile and execute C# code.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/
    - https://ijustwannared.team/2020/08/01/the-curious-case-of-aspnet_compiler-exe/
author: frack113
date: 2021-11-24
modified: 2025-02-24
tags:
    - attack.defense-evasion
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - ':\Windows\Microsoft.NET\Framework\'
            - ':\Windows\Microsoft.NET\Framework64\'
            - ':\Windows\Microsoft.NET\FrameworkArm\'
            - ':\Windows\Microsoft.NET\FrameworkArm64\'
        Image|endswith: '\aspnet_compiler.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
