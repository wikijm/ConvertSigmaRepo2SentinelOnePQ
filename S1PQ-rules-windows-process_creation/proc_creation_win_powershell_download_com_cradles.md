```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "[Type]::GetTypeFromCLSID(" and (tgt.process.cmdline contains "0002DF01-0000-0000-C000-000000000046" or tgt.process.cmdline contains "F6D90F16-9C73-11D3-B32E-00C04F990BB4" or tgt.process.cmdline contains "F5078F35-C551-11D3-89B9-0000F81FE221" or tgt.process.cmdline contains "88d96a0a-f192-11d4-a65f-0040963251e5" or tgt.process.cmdline contains "AFBA6B42-5692-48EA-8141-DC517DCF0EF1" or tgt.process.cmdline contains "AFB40FFD-B609-40A3-9828-F88BBE11E4E3" or tgt.process.cmdline contains "88d96a0b-f192-11d4-a65f-0040963251e5" or tgt.process.cmdline contains "2087c2f4-2cef-4953-a8ab-66779b670495" or tgt.process.cmdline contains "000209FF-0000-0000-C000-000000000046" or tgt.process.cmdline contains "00024500-0000-0000-C000-000000000046")))
```


# Original Sigma Rule:
```yaml
title: Potential COM Objects Download Cradles Usage - Process Creation
id: 02b64f1b-3f33-4e67-aede-ef3b0a5a8fcf
related:
    - id: 3c7d1587-3b13-439f-9941-7d14313dbdfe
      type: similar
status: test
description: Detects usage of COM objects that can be abused to download files in PowerShell by CLSID
references:
    - https://learn.microsoft.com/en-us/dotnet/api/system.type.gettypefromclsid?view=net-7.0
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=57
author: frack113
date: 2022-12-25
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    product: windows
    category: process_creation
detection:
    selection_1:
        CommandLine|contains: '[Type]::GetTypeFromCLSID('
    selection_2:
        CommandLine|contains:
            - '0002DF01-0000-0000-C000-000000000046'
            - 'F6D90F16-9C73-11D3-B32E-00C04F990BB4'
            - 'F5078F35-C551-11D3-89B9-0000F81FE221'
            - '88d96a0a-f192-11d4-a65f-0040963251e5'
            - 'AFBA6B42-5692-48EA-8141-DC517DCF0EF1'
            - 'AFB40FFD-B609-40A3-9828-F88BBE11E4E3'
            - '88d96a0b-f192-11d4-a65f-0040963251e5'
            - '2087c2f4-2cef-4953-a8ab-66779b670495'
            - '000209FF-0000-0000-C000-000000000046'
            - '00024500-0000-0000-C000-000000000046'
    condition: all of selection_*
falsepositives:
    - Legitimate use of the library
level: medium
```
