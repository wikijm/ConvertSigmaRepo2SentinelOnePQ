```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((not (tgt.process.image.path contains ".bin" or tgt.process.image.path contains ".cgi" or tgt.process.image.path contains ".com" or tgt.process.image.path contains ".exe" or tgt.process.image.path contains ".scr" or tgt.process.image.path contains ".tmp")) and (not ((tgt.process.image.path in ("System","Registry","MemCompression","vmmem")) or tgt.process.image.path contains ":\Windows\Installer\MSI" or tgt.process.image.path contains ":\Windows\System32\DriverStore\FileRepository\" or (tgt.process.image.path contains ":\Config.Msi\" and (tgt.process.image.path contains ".rbf" or tgt.process.image.path contains ".rbs")) or (src.process.image.path contains ":\Windows\Temp\" or tgt.process.image.path contains ":\Windows\Temp\") or tgt.process.image.path contains ":\$Extend\$Deleted\" or (tgt.process.image.path in ("-","")) or not (tgt.process.image.path matches "\.*"))) and (not (src.process.image.path contains ":\ProgramData\Avira\" or (tgt.process.image.path contains "NVIDIA\NvBackend\" and tgt.process.image.path contains ".dat") or ((tgt.process.image.path contains ":\Program Files (x86)\WINPAKPRO\" or tgt.process.image.path contains ":\Program Files\WINPAKPRO\") and tgt.process.image.path contains ".ngn") or (tgt.process.image.path contains ":\Program Files (x86)\MyQ\Server\pcltool.dll" or tgt.process.image.path contains ":\Program Files\MyQ\Server\pcltool.dll") or (tgt.process.image.path contains "\AppData\Local\Packages\" and tgt.process.image.path contains "\LocalState\rootfs\") or tgt.process.image.path contains "\LZMA_EXE" or tgt.process.image.path contains ":\Program Files\Mozilla Firefox\" or (src.process.image.path="C:\Windows\System32\services.exe" and tgt.process.image.path contains "com.docker.service")))))
```


# Original Sigma Rule:
```yaml
title: Execution of Suspicious File Type Extension
id: c09dad97-1c78-4f71-b127-7edb2b8e491a
status: test
description: |
    Detects whether the image specified in a process creation event doesn't refer to an ".exe" (or other known executable extension) file. This can be caused by process ghosting or other unorthodox methods to start a process.
    This rule might require some initial baselining to align with some third party tooling in the user environment.
references:
    - https://pentestlaboratories.com/2021/12/08/process-ghosting/
author: Max Altgelt (Nextron Systems)
date: 2021-12-09
modified: 2023-11-23
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    known_image_extension:
        Image|endswith:
            - '.bin'
            - '.cgi'
            - '.com'
            - '.exe'
            - '.scr'
            - '.tmp' # sadly many installers use this extension
    filter_main_image: # Windows utilities without extension
        Image:
            - 'System'
            - 'Registry'
            - 'MemCompression'
            - 'vmmem'
    filter_main_msi_installers:
        Image|contains: ':\Windows\Installer\MSI'
    filter_main_driver_store:
        Image|contains: ':\Windows\System32\DriverStore\FileRepository\'
    filter_main_msi_rollbackfiles:
        Image|contains: ':\Config.Msi\'
        Image|endswith:
            - '.rbf'
            - '.rbs'
    filter_main_windows_temp:
        - ParentImage|contains: ':\Windows\Temp\'
        - Image|contains: ':\Windows\Temp\'
    filter_main_deleted:
        Image|contains: ':\$Extend\$Deleted\'
    filter_main_empty:
        Image:
            - '-'
            - ''
    filter_main_null:
        Image: null
    filter_optional_avira:
        ParentImage|contains: ':\ProgramData\Avira\'
    filter_optional_nvidia:
        Image|contains: 'NVIDIA\NvBackend\'
        Image|endswith: '.dat'
    filter_optional_winpakpro:
        Image|contains:
            - ':\Program Files (x86)\WINPAKPRO\'
            - ':\Program Files\WINPAKPRO\'
        Image|endswith: '.ngn'
    filter_optional_myq_server:
        Image|endswith:
            - ':\Program Files (x86)\MyQ\Server\pcltool.dll'
            - ':\Program Files\MyQ\Server\pcltool.dll'
    filter_optional_wsl:
        Image|contains|all:
            - '\AppData\Local\Packages\'
            - '\LocalState\rootfs\'
    filter_optional_lzma_exe:
        Image|endswith: '\LZMA_EXE'
    filter_optional_firefox:
        Image|contains: ':\Program Files\Mozilla Firefox\'
    filter_optional_docker:
        ParentImage: 'C:\Windows\System32\services.exe'
        Image|endswith: 'com.docker.service'
    condition: not known_image_extension and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium
```
