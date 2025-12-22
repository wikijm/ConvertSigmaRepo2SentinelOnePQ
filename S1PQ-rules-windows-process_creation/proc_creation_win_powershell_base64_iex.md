```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "SUVYIChb" or tgt.process.cmdline contains "lFWCAoW" or tgt.process.cmdline contains "JRVggKF" or tgt.process.cmdline contains "aWV4IChb" or tgt.process.cmdline contains "lleCAoW" or tgt.process.cmdline contains "pZXggKF" or tgt.process.cmdline contains "aWV4IChOZX" or tgt.process.cmdline contains "lleCAoTmV3" or tgt.process.cmdline contains "pZXggKE5ld" or tgt.process.cmdline contains "SUVYIChOZX" or tgt.process.cmdline contains "lFWCAoTmV3" or tgt.process.cmdline contains "JRVggKE5ld" or tgt.process.cmdline contains "SUVYKF" or tgt.process.cmdline contains "lFWChb" or tgt.process.cmdline contains "JRVgoW" or tgt.process.cmdline contains "aWV4KF" or tgt.process.cmdline contains "lleChb" or tgt.process.cmdline contains "pZXgoW" or tgt.process.cmdline contains "aWV4KE5ld" or tgt.process.cmdline contains "lleChOZX" or tgt.process.cmdline contains "pZXgoTmV3" or tgt.process.cmdline contains "SUVYKE5ld" or tgt.process.cmdline contains "lFWChOZX" or tgt.process.cmdline contains "JRVgoTmV3" or tgt.process.cmdline contains "SUVYKCgn" or tgt.process.cmdline contains "lFWCgoJ" or tgt.process.cmdline contains "JRVgoKC" or tgt.process.cmdline contains "aWV4KCgn" or tgt.process.cmdline contains "lleCgoJ" or tgt.process.cmdline contains "pZXgoKC") or (tgt.process.cmdline contains "SQBFAFgAIAAoAFsA" or tgt.process.cmdline contains "kARQBYACAAKABbA" or tgt.process.cmdline contains "JAEUAWAAgACgAWw" or tgt.process.cmdline contains "aQBlAHgAIAAoAFsA" or tgt.process.cmdline contains "kAZQB4ACAAKABbA" or tgt.process.cmdline contains "pAGUAeAAgACgAWw" or tgt.process.cmdline contains "aQBlAHgAIAAoAE4AZQB3A" or tgt.process.cmdline contains "kAZQB4ACAAKABOAGUAdw" or tgt.process.cmdline contains "pAGUAeAAgACgATgBlAHcA" or tgt.process.cmdline contains "SQBFAFgAIAAoAE4AZQB3A" or tgt.process.cmdline contains "kARQBYACAAKABOAGUAdw" or tgt.process.cmdline contains "JAEUAWAAgACgATgBlAHcA")))
```


# Original Sigma Rule:
```yaml
title: PowerShell Base64 Encoded IEX Cmdlet
id: 88f680b8-070e-402c-ae11-d2914f2257f1
status: test
description: Detects usage of a base64 encoded "IEX" cmdlet in a process command line
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2019-08-23
modified: 2023-04-06
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|base64offset|contains:
              - 'IEX (['
              - 'iex (['
              - 'iex (New'
              - 'IEX (New'
              - 'IEX(['
              - 'iex(['
              - 'iex(New'
              - 'IEX(New'
              - "IEX(('"
              - "iex(('"
        # UTF16 LE
        - CommandLine|contains:
              - 'SQBFAFgAIAAoAFsA'
              - 'kARQBYACAAKABbA'
              - 'JAEUAWAAgACgAWw'
              - 'aQBlAHgAIAAoAFsA'
              - 'kAZQB4ACAAKABbA'
              - 'pAGUAeAAgACgAWw'
              - 'aQBlAHgAIAAoAE4AZQB3A'
              - 'kAZQB4ACAAKABOAGUAdw'
              - 'pAGUAeAAgACgATgBlAHcA'
              - 'SQBFAFgAIAAoAE4AZQB3A'
              - 'kARQBYACAAKABOAGUAdw'
              - 'JAEUAWAAgACgATgBlAHcA'
    condition: selection
falsepositives:
    - Unknown
level: high
```
