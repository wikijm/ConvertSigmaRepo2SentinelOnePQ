```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "Invoke-ATHRemoteFXvGPUDisablementCommand" or tgt.process.cmdline contains "Invoke-ATHRemoteFXvGPUDisableme"))
```


# Original Sigma Rule:
```yaml
title: RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses
id: a6fc3c46-23b8-4996-9ea2-573f4c4d88c5
related:
    - id: f65e22f9-819e-4f96-9c7b-498364ae7a25 # PS Classic
      type: similar
    - id: 38a7625e-b2cb-485d-b83d-aff137d859f4 # PS Module
      type: similar
    - id: cacef8fc-9d3d-41f7-956d-455c6e881bc5 # PS ScriptBlock
      type: similar
status: test
description: Detects calls to the AtomicTestHarnesses "Invoke-ATHRemoteFXvGPUDisablementCommand" which is designed to abuse the "RemoteFXvGPUDisablement.exe" binary to run custom PowerShell code via module load-order hijacking.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
    - https://github.com/redcanaryco/AtomicTestHarnesses/blob/7e1e4da116801e3d6fcc6bedb207064577e40572/TestHarnesses/T1218_SignedBinaryProxyExecution/InvokeRemoteFXvGPUDisablementCommand.ps1
author: frack113
date: 2021-07-13
modified: 2023-05-09
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-ATHRemoteFXvGPUDisablementCommand'
            - 'Invoke-ATHRemoteFXvGPUDisableme'
    condition: selection
falsepositives:
    - Unknown
level: high
```
