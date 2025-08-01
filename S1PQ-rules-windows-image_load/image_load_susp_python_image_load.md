```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (Description="Python Core" and (not (src.process.image.path contains "Python" or (src.process.image.path contains "C:\Program Files\" or src.process.image.path contains "C:\Program Files (x86)\" or src.process.image.path contains "C:\ProgramData\Anaconda3\"))) and (not not (src.process.image.path matches "\.*"))))
```


# Original Sigma Rule:
```yaml
title: Python Image Load By Non-Python Process
id: cbb56d62-4060-40f7-9466-d8aaf3123f83
status: test
description: Detects the image load of "Python Core" by a non-Python process. This might be indicative of a Python script bundled with Py2Exe.
references:
    - https://www.py2exe.org/
    - https://unit42.paloaltonetworks.com/unit-42-technical-analysis-seaduke/
author: Patrick St. John, OTR (Open Threat Research)
date: 2020-05-03
modified: 2023-09-18
tags:
    - attack.defense-evasion
    - attack.t1027.002
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Description: 'Python Core'
    filter_main_generic:
        - Image|contains: 'Python'  # FPs with python38.dll, python.exe etc.
        - Image|startswith:
              - 'C:\Program Files\'
              - 'C:\Program Files (x86)\'
              - 'C:\ProgramData\Anaconda3\' # Comment out if you don't use Anaconda in your environment
    filter_optional_aurora:
        Image: null
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate Py2Exe Binaries
    - Known false positive caused with Python Anaconda
level: medium
```
