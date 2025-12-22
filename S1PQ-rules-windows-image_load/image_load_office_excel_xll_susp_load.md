```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (src.process.image.path contains "\\excel.exe" and (module.path contains "\\Desktop\\" or module.path contains "\\Downloads\\" or module.path contains "\\Perflogs\\" or module.path contains "\\Temp\\" or module.path contains "\\Users\\Public\\" or module.path contains "\\Windows\\Tasks\\") and module.path contains ".xll"))
```


# Original Sigma Rule:
```yaml
title: Microsoft Excel Add-In Loaded From Uncommon Location
id: af4c4609-5755-42fe-8075-4effb49f5d44
related:
    - id: c5f4b5cb-4c25-4249-ba91-aa03626e3185
      type: derived
status: test
description: Detects Microsoft Excel loading an Add-In (.xll) file from an uncommon location
references:
    - https://www.mandiant.com/resources/blog/lnk-between-browsers
    - https://wazuh.com/blog/detecting-xll-files-used-for-dropping-fin7-jssloader-with-wazuh/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-12
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\excel.exe'
        ImageLoaded|contains:
            # Note: Add or remove locations from this list based on your internal policy
            - '\Desktop\'
            - '\Downloads\'
            - '\Perflogs\'
            - '\Temp\'
            - '\Users\Public\'
            - '\Windows\Tasks\'
        ImageLoaded|endswith: '.xll'
    condition: selection
falsepositives:
    - Some tuning might be required to allow or remove certain locations used by the rule if you consider them as safe locations
level: medium
```
