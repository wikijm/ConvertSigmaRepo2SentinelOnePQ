```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\action1_agent.exe" and tgt.process.image.path contains "\Windows\Action1\package_downloads\") or ((src.process.image.path contains "\cmd.exe" or src.process.image.path contains "\powershell.exe") and (src.process.cmdline contains "\Action1\scripts\Run_Command_" or src.process.cmdline contains "\Action1\scripts\Run_PowerShell_")) or tgt.process.image.path contains "\agent1_remote.exe"))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - Action1 Arbitrary Code Execution and Remote Sessions
id: aa3168fb-d594-4f93-a92d-7a9ba675b766
status: test
description: |
    Detects the execution of Action1 in order to execute arbitrary code or establish a remote session.

    Action1 is a powerful Remote Monitoring and Management tool that enables users to execute commands, scripts, and binaries.
    Through the web interface of action1, the administrator must create a new policy or an app to establish remote execution and then points that the agent is installed.

    Hunting Opportunity 1- Weed Out The Noise

    When threat actors execute a script, a command, or a binary through these new policies and apps, the names of these become visible in the command line during the execution process. Below is an example of the command line that contains the deployment of a binary through  a policy with name "test_app_1":

    ParentCommandLine: "C:\WINDOWS\Action1\action1_agent.exe schedule:Deploy_App__test_app_1_1681327673425 runaction:0"

    After establishing a baseline, we can split the command to extract the policy name and group all the policy names and inspect the results with a list of frequency occurrences.

    Hunting Opportunity 2 - Remote Sessions On Out Of Office Hours

    If you have admins within your environment using remote sessions to administer endpoints, you can create a threat-hunting query and modify the time of the initiated sessions looking for abnormal activity.
references:
    - https://twitter.com/Kostastsale/status/1646256901506605063?s=20
    - https://www.action1.com/documentation/
author: '@kostastsale'
date: 2023-04-13
tags:
    - attack.command-and-control
    - attack.t1219.002
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection_app_deployment_exec:
        ParentImage|endswith: '\action1_agent.exe'
        Image|contains: '\Windows\Action1\package_downloads\'
    selection_command_exec:
        ParentImage|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
        ParentCommandLine|contains:
            - '\Action1\scripts\Run_Command_'
            - '\Action1\scripts\Run_PowerShell_'
    selection_remote_session_init:
        Image|endswith: '\agent1_remote.exe'
    condition: 1 of selection_*
falsepositives:
    - If Action1 is among the approved software in your environment, you might find that this is a noisy query. See description for ideas on how to alter this query and start looking for suspicious activities.
level: medium
```
