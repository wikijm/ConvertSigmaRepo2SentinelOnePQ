```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "AddSecurityPackage" or tgt.process.cmdline contains "AdjustTokenPrivileges" or tgt.process.cmdline contains "Advapi32" or tgt.process.cmdline contains "CloseHandle" or tgt.process.cmdline contains "CreateProcessWithToken" or tgt.process.cmdline contains "CreatePseudoConsole" or tgt.process.cmdline contains "CreateRemoteThread" or tgt.process.cmdline contains "CreateThread" or tgt.process.cmdline contains "CreateUserThread" or tgt.process.cmdline contains "DangerousGetHandle" or tgt.process.cmdline contains "DuplicateTokenEx" or tgt.process.cmdline contains "EnumerateSecurityPackages" or tgt.process.cmdline contains "FreeHGlobal" or tgt.process.cmdline contains "FreeLibrary" or tgt.process.cmdline contains "GetDelegateForFunctionPointer" or tgt.process.cmdline contains "GetLogonSessionData" or tgt.process.cmdline contains "GetModuleHandle" or tgt.process.cmdline contains "GetProcAddress" or tgt.process.cmdline contains "GetProcessHandle" or tgt.process.cmdline contains "GetTokenInformation" or tgt.process.cmdline contains "ImpersonateLoggedOnUser" or tgt.process.cmdline contains "kernel32" or tgt.process.cmdline contains "LoadLibrary" or tgt.process.cmdline contains "memcpy" or tgt.process.cmdline contains "MiniDumpWriteDump" or tgt.process.cmdline contains "ntdll" or tgt.process.cmdline contains "OpenDesktop" or tgt.process.cmdline contains "OpenProcess" or tgt.process.cmdline contains "OpenProcessToken" or tgt.process.cmdline contains "OpenThreadToken" or tgt.process.cmdline contains "OpenWindowStation" or tgt.process.cmdline contains "PtrToString" or tgt.process.cmdline contains "QueueUserApc" or tgt.process.cmdline contains "ReadProcessMemory" or tgt.process.cmdline contains "RevertToSelf" or tgt.process.cmdline contains "RtlCreateUserThread" or tgt.process.cmdline contains "secur32" or tgt.process.cmdline contains "SetThreadToken" or tgt.process.cmdline contains "VirtualAlloc" or tgt.process.cmdline contains "VirtualFree" or tgt.process.cmdline contains "VirtualProtect" or tgt.process.cmdline contains "WaitForSingleObject" or tgt.process.cmdline contains "WriteInt32" or tgt.process.cmdline contains "WriteProcessMemory" or tgt.process.cmdline contains "ZeroFreeGlobalAllocUnicode") and (not ((tgt.process.image.path contains "\\MpCmdRun.exe" and tgt.process.cmdline contains "GetLoadLibraryWAddress32") or (src.process.image.path contains "\\CompatTelRunner.exe" and (tgt.process.cmdline contains "FreeHGlobal" or tgt.process.cmdline contains "PtrToString" or tgt.process.cmdline contains "kernel32" or tgt.process.cmdline contains "CloseHandle"))))))
```


# Original Sigma Rule:
```yaml
title: Potential WinAPI Calls Via CommandLine
id: ba3f5c1b-6272-4119-9dbd-0bc8d21c2702
related:
    - id: 03d83090-8cba-44a0-b02f-0b756a050306
      type: derived
status: test
description: Detects the use of WinAPI Functions via the commandline. As seen used by threat actors via the tool winapiexec
references:
    - https://twitter.com/m417z/status/1566674631788007425
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-06
modified: 2025-03-06
tags:
    - attack.execution
    - attack.t1106
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'AddSecurityPackage'
            - 'AdjustTokenPrivileges'
            - 'Advapi32'
            - 'CloseHandle'
            - 'CreateProcessWithToken'
            - 'CreatePseudoConsole'
            - 'CreateRemoteThread'
            - 'CreateThread'
            - 'CreateUserThread'
            - 'DangerousGetHandle'
            - 'DuplicateTokenEx'
            - 'EnumerateSecurityPackages'
            - 'FreeHGlobal'
            - 'FreeLibrary'
            - 'GetDelegateForFunctionPointer'
            - 'GetLogonSessionData'
            - 'GetModuleHandle'
            - 'GetProcAddress'
            - 'GetProcessHandle'
            - 'GetTokenInformation'
            - 'ImpersonateLoggedOnUser'
            - 'kernel32'
            - 'LoadLibrary'
            - 'memcpy'
            - 'MiniDumpWriteDump'
            # - 'msvcrt'
            - 'ntdll'
            - 'OpenDesktop'
            - 'OpenProcess'
            - 'OpenProcessToken'
            - 'OpenThreadToken'
            - 'OpenWindowStation'
            - 'PtrToString'
            - 'QueueUserApc'
            - 'ReadProcessMemory'
            - 'RevertToSelf'
            - 'RtlCreateUserThread'
            - 'secur32'
            - 'SetThreadToken'
            # - 'user32'
            - 'VirtualAlloc'
            - 'VirtualFree'
            - 'VirtualProtect'
            - 'WaitForSingleObject'
            - 'WriteInt32'
            - 'WriteProcessMemory'
            - 'ZeroFreeGlobalAllocUnicode'
    filter_optional_mpcmdrun:
        Image|endswith: '\MpCmdRun.exe'
        CommandLine|contains: 'GetLoadLibraryWAddress32'
    filter_optional_compatTelRunner:
        ParentImage|endswith: '\CompatTelRunner.exe'
        CommandLine|contains:
            - 'FreeHGlobal'
            - 'PtrToString'
            - 'kernel32'
            - 'CloseHandle'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - Some legitimate action or applications may use these functions. Investigate further to determine the legitimacy of the activity.
level: high
```
