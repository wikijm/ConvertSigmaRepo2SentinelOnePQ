```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe") and (tgt.process.cmdline contains " -windowstyle h " or tgt.process.cmdline contains " -windowstyl h" or tgt.process.cmdline contains " -windowsty h" or tgt.process.cmdline contains " -windowst h" or tgt.process.cmdline contains " -windows h" or tgt.process.cmdline contains " -windo h" or tgt.process.cmdline contains " -wind h" or tgt.process.cmdline contains " -win h" or tgt.process.cmdline contains " -wi h" or tgt.process.cmdline contains " -win h " or tgt.process.cmdline contains " -win hi " or tgt.process.cmdline contains " -win hid " or tgt.process.cmdline contains " -win hidd " or tgt.process.cmdline contains " -win hidde " or tgt.process.cmdline contains " -NoPr " or tgt.process.cmdline contains " -NoPro " or tgt.process.cmdline contains " -NoProf " or tgt.process.cmdline contains " -NoProfi " or tgt.process.cmdline contains " -NoProfil " or tgt.process.cmdline contains " -nonin " or tgt.process.cmdline contains " -nonint " or tgt.process.cmdline contains " -noninte " or tgt.process.cmdline contains " -noninter " or tgt.process.cmdline contains " -nonintera " or tgt.process.cmdline contains " -noninterac " or tgt.process.cmdline contains " -noninteract " or tgt.process.cmdline contains " -noninteracti " or tgt.process.cmdline contains " -noninteractiv " or tgt.process.cmdline contains " -ec " or tgt.process.cmdline contains " -encodedComman " or tgt.process.cmdline contains " -encodedComma " or tgt.process.cmdline contains " -encodedComm " or tgt.process.cmdline contains " -encodedCom " or tgt.process.cmdline contains " -encodedCo " or tgt.process.cmdline contains " -encodedC " or tgt.process.cmdline contains " -encoded " or tgt.process.cmdline contains " -encode " or tgt.process.cmdline contains " -encod " or tgt.process.cmdline contains " -enco " or tgt.process.cmdline contains " -en " or tgt.process.cmdline contains " -executionpolic " or tgt.process.cmdline contains " -executionpoli " or tgt.process.cmdline contains " -executionpol " or tgt.process.cmdline contains " -executionpo " or tgt.process.cmdline contains " -executionp " or tgt.process.cmdline contains " -execution bypass" or tgt.process.cmdline contains " -executio bypass" or tgt.process.cmdline contains " -executi bypass" or tgt.process.cmdline contains " -execut bypass" or tgt.process.cmdline contains " -execu bypass" or tgt.process.cmdline contains " -exec bypass" or tgt.process.cmdline contains " -exe bypass" or tgt.process.cmdline contains " -ex bypass" or tgt.process.cmdline contains " -ep bypass" or tgt.process.cmdline contains " /windowstyle h " or tgt.process.cmdline contains " /windowstyl h" or tgt.process.cmdline contains " /windowsty h" or tgt.process.cmdline contains " /windowst h" or tgt.process.cmdline contains " /windows h" or tgt.process.cmdline contains " /windo h" or tgt.process.cmdline contains " /wind h" or tgt.process.cmdline contains " /win h" or tgt.process.cmdline contains " /wi h" or tgt.process.cmdline contains " /win h " or tgt.process.cmdline contains " /win hi " or tgt.process.cmdline contains " /win hid " or tgt.process.cmdline contains " /win hidd " or tgt.process.cmdline contains " /win hidde " or tgt.process.cmdline contains " /NoPr " or tgt.process.cmdline contains " /NoPro " or tgt.process.cmdline contains " /NoProf " or tgt.process.cmdline contains " /NoProfi " or tgt.process.cmdline contains " /NoProfil " or tgt.process.cmdline contains " /nonin " or tgt.process.cmdline contains " /nonint " or tgt.process.cmdline contains " /noninte " or tgt.process.cmdline contains " /noninter " or tgt.process.cmdline contains " /nonintera " or tgt.process.cmdline contains " /noninterac " or tgt.process.cmdline contains " /noninteract " or tgt.process.cmdline contains " /noninteracti " or tgt.process.cmdline contains " /noninteractiv " or tgt.process.cmdline contains " /ec " or tgt.process.cmdline contains " /encodedComman " or tgt.process.cmdline contains " /encodedComma " or tgt.process.cmdline contains " /encodedComm " or tgt.process.cmdline contains " /encodedCom " or tgt.process.cmdline contains " /encodedCo " or tgt.process.cmdline contains " /encodedC " or tgt.process.cmdline contains " /encoded " or tgt.process.cmdline contains " /encode " or tgt.process.cmdline contains " /encod " or tgt.process.cmdline contains " /enco " or tgt.process.cmdline contains " /en " or tgt.process.cmdline contains " /executionpolic " or tgt.process.cmdline contains " /executionpoli " or tgt.process.cmdline contains " /executionpol " or tgt.process.cmdline contains " /executionpo " or tgt.process.cmdline contains " /executionp " or tgt.process.cmdline contains " /execution bypass" or tgt.process.cmdline contains " /executio bypass" or tgt.process.cmdline contains " /executi bypass" or tgt.process.cmdline contains " /execut bypass" or tgt.process.cmdline contains " /execu bypass" or tgt.process.cmdline contains " /exec bypass" or tgt.process.cmdline contains " /exe bypass" or tgt.process.cmdline contains " /ex bypass" or tgt.process.cmdline contains " /ep bypass")))
```


# Original Sigma Rule:
```yaml
title: Suspicious PowerShell Parameter Substring
id: 36210e0d-5b19-485d-a087-c096088885f0
status: test
description: Detects suspicious PowerShell invocation with a parameter substring
references:
    - http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier
author: Florian Roth (Nextron Systems), Daniel Bohannon (idea), Roberto Rodriguez (Fix)
date: 2019-01-16
modified: 2022-07-14
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - ' -windowstyle h '
            - ' -windowstyl h'
            - ' -windowsty h'
            - ' -windowst h'
            - ' -windows h'
            - ' -windo h'
            - ' -wind h'
            - ' -win h'
            - ' -wi h'
            - ' -win h '
            - ' -win hi '
            - ' -win hid '
            - ' -win hidd '
            - ' -win hidde '
            - ' -NoPr '
            - ' -NoPro '
            - ' -NoProf '
            - ' -NoProfi '
            - ' -NoProfil '
            - ' -nonin '
            - ' -nonint '
            - ' -noninte '
            - ' -noninter '
            - ' -nonintera '
            - ' -noninterac '
            - ' -noninteract '
            - ' -noninteracti '
            - ' -noninteractiv '
            - ' -ec '
            - ' -encodedComman '
            - ' -encodedComma '
            - ' -encodedComm '
            - ' -encodedCom '
            - ' -encodedCo '
            - ' -encodedC '
            - ' -encoded '
            - ' -encode '
            - ' -encod '
            - ' -enco '
            - ' -en '
            - ' -executionpolic '
            - ' -executionpoli '
            - ' -executionpol '
            - ' -executionpo '
            - ' -executionp '
            - ' -execution bypass'
            - ' -executio bypass'
            - ' -executi bypass'
            - ' -execut bypass'
            - ' -execu bypass'
            - ' -exec bypass'
            - ' -exe bypass'
            - ' -ex bypass'
            - ' -ep bypass'
            - ' /windowstyle h '
            - ' /windowstyl h'
            - ' /windowsty h'
            - ' /windowst h'
            - ' /windows h'
            - ' /windo h'
            - ' /wind h'
            - ' /win h'
            - ' /wi h'
            - ' /win h '
            - ' /win hi '
            - ' /win hid '
            - ' /win hidd '
            - ' /win hidde '
            - ' /NoPr '
            - ' /NoPro '
            - ' /NoProf '
            - ' /NoProfi '
            - ' /NoProfil '
            - ' /nonin '
            - ' /nonint '
            - ' /noninte '
            - ' /noninter '
            - ' /nonintera '
            - ' /noninterac '
            - ' /noninteract '
            - ' /noninteracti '
            - ' /noninteractiv '
            - ' /ec '
            - ' /encodedComman '
            - ' /encodedComma '
            - ' /encodedComm '
            - ' /encodedCom '
            - ' /encodedCo '
            - ' /encodedC '
            - ' /encoded '
            - ' /encode '
            - ' /encod '
            - ' /enco '
            - ' /en '
            - ' /executionpolic '
            - ' /executionpoli '
            - ' /executionpol '
            - ' /executionpo '
            - ' /executionp '
            - ' /execution bypass'
            - ' /executio bypass'
            - ' /executi bypass'
            - ' /execut bypass'
            - ' /execu bypass'
            - ' /exec bypass'
            - ' /exe bypass'
            - ' /ex bypass'
            - ' /ep bypass'
    condition: selection
falsepositives:
    - Unknown
level: high
```
