```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path="C:\Windows\System32\MicrosoftAccountTokenProvider.dll" and (not ((src.process.image.path contains "C:\Windows\System32\" or src.process.image.path contains "C:\Windows\SysWOW64\") and src.process.image.path contains "\BackgroundTaskHost.exe")) and (not (((src.process.image.path contains "C:\Program Files\Microsoft Visual Studio\" or src.process.image.path contains "C:\Program Files (x86)\Microsoft Visual Studio\") and src.process.image.path contains "\IDE\devenv.exe") or (src.process.image.path in ("C:\Program Files (x86)\Internet Explorer\iexplore.exe","C:\Program Files\Internet Explorer\iexplore.exe")) or (src.process.image.path contains "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\" or src.process.image.path contains "\WindowsApps\MicrosoftEdge.exe" or (src.process.image.path in ("C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe","C:\Program Files\Microsoft\Edge\Application\msedge.exe"))) or ((src.process.image.path contains "C:\Program Files (x86)\Microsoft\EdgeCore\" or src.process.image.path contains "C:\Program Files\Microsoft\EdgeCore\") and (src.process.image.path contains "\msedge.exe" or src.process.image.path contains "\msedgewebview2.exe")) or src.process.image.path contains "\AppData\Local\Microsoft\OneDrive\OneDrive.exe" or not (src.process.image.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Potential Azure Browser SSO Abuse
id: 50f852e6-af22-4c78-9ede-42ef36aa3453
status: test
description: |
    Detects abusing Azure Browser SSO by requesting OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser.
    An attacker can use this to authenticate to Azure AD in a browser as that user.
references:
    - https://posts.specterops.io/requesting-azure-ad-request-tokens-on-azure-ad-joined-machines-for-browser-sso-2b0409caad30
author: Den Iuzvyk
date: 2020-07-15
modified: 2023-04-18
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded: 'C:\Windows\System32\MicrosoftAccountTokenProvider.dll'
    filter_main_bgtaskhost:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
        Image|endswith: '\BackgroundTaskHost.exe'
        # CommandLine|contains: '-ServerNameBackgroundTaskHost.WebAccountProvider'
    filter_optional_devenv:
        Image|startswith:
            - 'C:\Program Files\Microsoft Visual Studio\'
            - 'C:\Program Files (x86)\Microsoft Visual Studio\'
        Image|endswith: '\IDE\devenv.exe'
    filter_optional_ie:
        Image:
            - 'C:\Program Files (x86)\Internet Explorer\iexplore.exe'
            - 'C:\Program Files\Internet Explorer\iexplore.exe'
    filter_optional_edge_1:
        - Image|startswith: 'C:\Program Files (x86)\Microsoft\EdgeWebView\Application\'
        - Image|endswith: '\WindowsApps\MicrosoftEdge.exe'
        - Image:
              - 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
              - 'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
    filter_optional_edge_2:
        Image|startswith:
            - 'C:\Program Files (x86)\Microsoft\EdgeCore\'
            - 'C:\Program Files\Microsoft\EdgeCore\'
        Image|endswith:
            - '\msedge.exe'
            - '\msedgewebview2.exe'
    filter_optional_onedrive:
        Image|endswith: '\AppData\Local\Microsoft\OneDrive\OneDrive.exe'
    filter_optional_null:
        Image: null
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - False positives are expected since this rules is only looking for the DLL load event. This rule is better used in correlation with related activity
level: low
```
