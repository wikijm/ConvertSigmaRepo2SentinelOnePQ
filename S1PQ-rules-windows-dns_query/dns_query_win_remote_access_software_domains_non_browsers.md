```sql
// Translated content (automatically translated on 02-08-2025 02:10:48):
event.category="DNS" and (endpoint.os="windows" and (((event.dns.request contains "agent.jumpcloud.com" or event.dns.request contains "agentreporting.atera.com" or event.dns.request contains "ammyy.com" or event.dns.request contains "api.parsec.app" or event.dns.request contains "api.playanext.com" or event.dns.request contains "api.splashtop.com" or event.dns.request contains "app.atera.com" or event.dns.request contains "assist.zoho.com" or event.dns.request contains "authentication.logmeininc.com" or event.dns.request contains "beyondtrustcloud.com" or event.dns.request contains "cdn.kaseya.net" or event.dns.request contains "client.teamviewer.com" or event.dns.request contains "comserver.corporate.beanywhere.com" or event.dns.request contains "control.connectwise.com" or event.dns.request contains "downloads.zohocdn.com" or event.dns.request contains "dwservice.net" or event.dns.request contains "express.gotoassist.com" or event.dns.request contains "getgo.com" or event.dns.request contains "getscreen.me" or event.dns.request contains "integratedchat.teamviewer.com" or event.dns.request contains "join.zoho.com" or event.dns.request contains "kickstart.jumpcloud.com" or event.dns.request contains "license.bomgar.com" or event.dns.request contains "logmein-gateway.com" or event.dns.request contains "logmein.com" or event.dns.request contains "logmeincdn.http.internapcdn.net" or event.dns.request contains "n-able.com" or event.dns.request contains "net.anydesk.com" or event.dns.request contains "netsupportsoftware.com" or event.dns.request contains "parsecusercontent.com" or event.dns.request contains "pubsub.atera.com" or event.dns.request contains "relay.kaseya.net" or event.dns.request contains "relay.screenconnect.com" or event.dns.request contains "relay.splashtop.com" or event.dns.request contains "remoteassistance.support.services.microsoft.com" or event.dns.request contains "remotedesktop-pa.googleapis.com" or event.dns.request contains "remoteutilities.com" or event.dns.request contains "secure.logmeinrescue.com" or event.dns.request contains "services.vnc.com" or event.dns.request contains "static.remotepc.com" or event.dns.request contains "swi-rc.com" or event.dns.request contains "swi-tc.com" or event.dns.request contains "tailscale.com" or event.dns.request contains "telemetry.servers.qetqo.com" or event.dns.request contains "tmate.io" or event.dns.request contains "twingate.com" or event.dns.request contains "zohoassist.com") or (event.dns.request contains ".rustdesk.com" and event.dns.request contains "rs-")) and (not ((src.process.image.path in ("C:\Program Files\Google\Chrome\Application\chrome.exe","C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")) or (src.process.image.path in ("C:\Program Files\Mozilla Firefox\firefox.exe","C:\Program Files (x86)\Mozilla Firefox\firefox.exe")) or (src.process.image.path in ("C:\Program Files (x86)\Internet Explorer\iexplore.exe","C:\Program Files\Internet Explorer\iexplore.exe")) or (src.process.image.path contains "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\" or src.process.image.path contains "\WindowsApps\MicrosoftEdge.exe" or (src.process.image.path in ("C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe","C:\Program Files\Microsoft\Edge\Application\msedge.exe"))) or ((src.process.image.path contains "C:\Program Files (x86)\Microsoft\EdgeCore\" or src.process.image.path contains "C:\Program Files\Microsoft\EdgeCore\") and (src.process.image.path contains "\msedge.exe" or src.process.image.path contains "\msedgewebview2.exe")) or src.process.image.path contains "\safari.exe" or (src.process.image.path contains "\MsMpEng.exe" or src.process.image.path contains "\MsSense.exe") or (src.process.image.path contains "\brave.exe" and src.process.image.path contains "C:\Program Files\BraveSoftware\") or (src.process.image.path contains "\AppData\Local\Maxthon\" and src.process.image.path contains "\maxthon.exe") or (src.process.image.path contains "\AppData\Local\Programs\Opera\" and src.process.image.path contains "\opera.exe") or ((src.process.image.path contains "C:\Program Files\SeaMonkey\" or src.process.image.path contains "C:\Program Files (x86)\SeaMonkey\") and src.process.image.path contains "\seamonkey.exe") or (src.process.image.path contains "\AppData\Local\Vivaldi\" and src.process.image.path contains "\vivaldi.exe") or ((src.process.image.path contains "C:\Program Files\Naver\Naver Whale\" or src.process.image.path contains "C:\Program Files (x86)\Naver\Naver Whale\") and src.process.image.path contains "\whale.exe") or src.process.image.path contains "\Tor Browser\" or ((src.process.image.path contains "C:\Program Files\Waterfox\" or src.process.image.path contains "C:\Program Files (x86)\Waterfox\") and src.process.image.path contains "\Waterfox.exe") or (src.process.image.path contains "\AppData\Local\Programs\midori-ng\" and src.process.image.path contains "\Midori Next Generation.exe") or ((src.process.image.path contains "C:\Program Files\SlimBrowser\" or src.process.image.path contains "C:\Program Files (x86)\SlimBrowser\") and src.process.image.path contains "\slimbrowser.exe") or (src.process.image.path contains "\AppData\Local\Flock\" and src.process.image.path contains "\Flock.exe") or (src.process.image.path contains "\AppData\Local\Phoebe\" and src.process.image.path contains "\Phoebe.exe") or ((src.process.image.path contains "C:\Program Files\Falkon\" or src.process.image.path contains "C:\Program Files (x86)\Falkon\") and src.process.image.path contains "\falkon.exe") or ((src.process.image.path contains "C:\Program Files (x86)\Avant Browser\" or src.process.image.path contains "C:\Program Files\Avant Browser\") and src.process.image.path contains "\avant.exe")))))
```


# Original Sigma Rule:
```yaml
title: DNS Query To Remote Access Software Domain From Non-Browser App
id: 4d07b1f4-cb00-4470-b9f8-b0191d48ff52
related:
    - id: 71ba22cb-8a01-42e2-a6dd-5bf9b547498f
      type: obsolete
    - id: 7c4cf8e0-1362-48b2-a512-b606d2065d7d
      type: obsolete
    - id: ed785237-70fa-46f3-83b6-d264d1dc6eb4
      type: obsolete
status: test
description: |
    An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
    These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
    Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-4---gotoassist-files-detected-test-on-windows
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-3---logmein-files-detected-test-on-windows
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-6---ammyy-admin-software-execution
    - https://redcanary.com/blog/misbehaving-rats/
    - https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/hunting-for-omi-vulnerability-exploitation-with-azure-sentinel/ba-p/2764093
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
    - https://blog.sekoia.io/scattered-spider-laying-new-eggs/
    - https://learn.microsoft.com/en-us/windows/client-management/client-tools/quick-assist#disable-quick-assist-within-your-organization
author: frack113, Connor Martin
date: 2022-07-11
modified: 2024-12-17
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    product: windows
    category: dns_query
detection:
    selection_generic:
        QueryName|endswith:
            - 'agent.jumpcloud.com'
            - 'agentreporting.atera.com'
            - 'ammyy.com'
            - 'api.parsec.app'
            - 'api.playanext.com'
            - 'api.splashtop.com'
            - 'app.atera.com'
            - 'assist.zoho.com'
            - 'authentication.logmeininc.com'
            - 'beyondtrustcloud.com'
            - 'cdn.kaseya.net'
            - 'client.teamviewer.com'
            - 'comserver.corporate.beanywhere.com'
            - 'control.connectwise.com'
            - 'downloads.zohocdn.com'
            - 'dwservice.net'
            - 'express.gotoassist.com'
            - 'getgo.com'
            - 'getscreen.me'  # https://x.com/malmoeb/status/1868757130624614860?s=12&t=C0_T_re0wRP_NfKa27Xw9w
            - 'integratedchat.teamviewer.com'
            - 'join.zoho.com'
            - 'kickstart.jumpcloud.com'
            - 'license.bomgar.com'
            - 'logmein-gateway.com'
            - 'logmein.com'
            - 'logmeincdn.http.internapcdn.net'
            - 'n-able.com'
            - 'net.anydesk.com'
            - 'netsupportsoftware.com' # For NetSupport Manager RAT
            - 'parsecusercontent.com'
            - 'pubsub.atera.com'
            - 'relay.kaseya.net'
            - 'relay.screenconnect.com'
            - 'relay.splashtop.com'
            - 'remoteassistance.support.services.microsoft.com' # Quick Assist Application
            - 'remotedesktop-pa.googleapis.com'
            - 'remoteutilities.com' # Usage of Remote Utilities RAT
            - 'secure.logmeinrescue.com'
            - 'services.vnc.com'
            - 'static.remotepc.com'
            - 'swi-rc.com'
            - 'swi-tc.com'
            - 'tailscale.com' # Scattered Spider threat group used this RMM tool
            - 'telemetry.servers.qetqo.com'
            - 'tmate.io'
            - 'twingate.com'  # Scattered Spider threat group used this RMM tool
            - 'zohoassist.com'
    selection_rustdesk:  # https://twitter.com/malmoeb/status/1668504345132822531?s=20 and https://www.adamsdesk.com/posts/rustdesk-not-connecting/ mention this pattern
        QueryName|endswith: '.rustdesk.com'
        QueryName|startswith: 'rs-'
    # Exclude browsers for legitimate visits of the domains mentioned above
    # Add missing browsers you use and exclude the ones you don't
    filter_optional_chrome:
        Image:
            - 'C:\Program Files\Google\Chrome\Application\chrome.exe'
            - 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
    filter_optional_firefox:
        Image:
            - 'C:\Program Files\Mozilla Firefox\firefox.exe'
            - 'C:\Program Files (x86)\Mozilla Firefox\firefox.exe'
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
    filter_optional_safari:
        Image|endswith: '\safari.exe'
    filter_optional_defender:
        Image|endswith:
            - '\MsMpEng.exe' # Microsoft Defender executable
            - '\MsSense.exe' # Windows Defender Advanced Threat Protection Service Executable
    filter_optional_brave:
        Image|endswith: '\brave.exe'
        Image|startswith: 'C:\Program Files\BraveSoftware\'
    filter_optional_maxthon:
        Image|contains: '\AppData\Local\Maxthon\'
        Image|endswith: '\maxthon.exe'
    filter_optional_opera:
        Image|contains: '\AppData\Local\Programs\Opera\'
        Image|endswith: '\opera.exe'
    filter_optional_seamonkey:
        Image|startswith:
            - 'C:\Program Files\SeaMonkey\'
            - 'C:\Program Files (x86)\SeaMonkey\'
        Image|endswith: '\seamonkey.exe'
    filter_optional_vivaldi:
        Image|contains: '\AppData\Local\Vivaldi\'
        Image|endswith: '\vivaldi.exe'
    filter_optional_whale:
        Image|startswith:
            - 'C:\Program Files\Naver\Naver Whale\'
            - 'C:\Program Files (x86)\Naver\Naver Whale\'
        Image|endswith: '\whale.exe'
    filter_optional_tor:
        Image|contains: '\Tor Browser\'
    filter_optional_whaterfox:
        Image|startswith:
            - 'C:\Program Files\Waterfox\'
            - 'C:\Program Files (x86)\Waterfox\'
        Image|endswith: '\Waterfox.exe'
    filter_optional_midori:
        Image|contains: '\AppData\Local\Programs\midori-ng\'
        Image|endswith: '\Midori Next Generation.exe'
    filter_optional_slimbrowser:
        Image|startswith:
            - 'C:\Program Files\SlimBrowser\'
            - 'C:\Program Files (x86)\SlimBrowser\'
        Image|endswith: '\slimbrowser.exe'
    filter_optional_flock:
        Image|contains: '\AppData\Local\Flock\'
        Image|endswith: '\Flock.exe'
    filter_optional_phoebe:
        Image|contains: '\AppData\Local\Phoebe\'
        Image|endswith: '\Phoebe.exe'
    filter_optional_falkon:
        Image|startswith:
            - 'C:\Program Files\Falkon\'
            - 'C:\Program Files (x86)\Falkon\'
        Image|endswith: '\falkon.exe'
    filter_optional_avant:
        Image|startswith:
            - 'C:\Program Files (x86)\Avant Browser\'
            - 'C:\Program Files\Avant Browser\'
        Image|endswith: '\avant.exe'
    condition: 1 of selection_* and not 1 of filter_optional_*
falsepositives:
    - Likely with other browser software. Apply additional filters for any other browsers you might use.
level: medium
```
