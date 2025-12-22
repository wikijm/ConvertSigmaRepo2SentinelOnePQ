```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "DumpCreds" or tgt.process.cmdline contains "mimikatz") or (tgt.process.cmdline contains "::aadcookie" or tgt.process.cmdline contains "::detours" or tgt.process.cmdline contains "::memssp" or tgt.process.cmdline contains "::mflt" or tgt.process.cmdline contains "::ncroutemon" or tgt.process.cmdline contains "::ngcsign" or tgt.process.cmdline contains "::printnightmare" or tgt.process.cmdline contains "::skeleton" or tgt.process.cmdline contains "::preshutdown" or tgt.process.cmdline contains "::mstsc" or tgt.process.cmdline contains "::multirdp") or (tgt.process.cmdline contains "rpc::" or tgt.process.cmdline contains "token::" or tgt.process.cmdline contains "crypto::" or tgt.process.cmdline contains "dpapi::" or tgt.process.cmdline contains "sekurlsa::" or tgt.process.cmdline contains "kerberos::" or tgt.process.cmdline contains "lsadump::" or tgt.process.cmdline contains "privilege::" or tgt.process.cmdline contains "process::" or tgt.process.cmdline contains "vault::")))
```


# Original Sigma Rule:
```yaml
title: HackTool - Mimikatz Execution
id: a642964e-bead-4bed-8910-1bb4d63e3b4d
status: test
description: Detection well-known mimikatz command line arguments
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    - https://tools.thehacker.recipes/mimikatz/modules
author: Teymur Kheirkhabarov, oscd.community, David ANDRE (additional keywords), Tim Shelton
date: 2019-10-22
modified: 2023-02-21
tags:
    - attack.credential-access
    - attack.t1003.001
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.005
    - attack.t1003.006
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools_name:
        CommandLine|contains:
            - 'DumpCreds'
            - 'mimikatz'
    selection_function_names: # To cover functions from modules that are not in module_names
        CommandLine|contains:
            - '::aadcookie' # misc module
            - '::detours' # misc module
            - '::memssp' # misc module
            - '::mflt' # misc module
            - '::ncroutemon' # misc module
            - '::ngcsign' # misc module
            - '::printnightmare' # misc module
            - '::skeleton' # misc module
            - '::preshutdown'  # service module
            - '::mstsc'  # ts module
            - '::multirdp'  # ts module
    selection_module_names:
        CommandLine|contains:
            - 'rpc::'
            - 'token::'
            - 'crypto::'
            - 'dpapi::'
            - 'sekurlsa::'
            - 'kerberos::'
            - 'lsadump::'
            - 'privilege::'
            - 'process::'
            - 'vault::'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: high
```
