#Defender for Identity tips
##Installation tips

###Capacity planning
Make sure you start with this capacity planning tool execution before anything else.
https://learn.microsoft.com/en-us/defender-for-identity/capacity-planning

###Script to check installation prerequisites
Recently this nice Test-MdiReadiness.ps1 script has been made available, make sure to leverage it to simplify deployment.
See https://learn.microsoft.com/en-us/defender-for-identity/deploy-defender-identity

###Proxy requirements notes
"Blocking Internet Access for Domain Controllers" official AD security recommendation was updated precisely to cover Defender for Identity internet requirements: 
>Whilst this hybrid model exists in any organization, Microsoft recommends cloud powered protection of those on-premises identities using Microsoft Defender for Identity. The configuration of the Defender for Identity sensor on domain controllers and AD FS servers allows for a highly secured, one-way connection to the cloud service through a proxy and to specific endpoints. A complete explanation on how to configure this proxy connection can be found in the technical documentation for Defender for Identity. This tightly controlled configuration ensures that the risk of connecting these servers to the cloud service is mitigated, and organizations benefit from the increase in protection capabilities Defender for Identity offers. Microsoft also recommends that these servers are protected with cloud powered endpoint detection like Microsoft Defender for Servers. 
Source: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack#blocking-internet-access-for-domain-controllers

##Defender for Identity Health Alerts
Defender for Identity may generate health alerts in case of an health-related issue. See https://learn.microsoft.com/en-us/defender-for-identity/health-alerts for more information.
Unfortunately at the time of this writing (march 2023), those alerts are not available through an API.

The goal of this section is to describe one workaround to get those alerts automatically sent to your Log Analytics workspace for centralized monitoring purposes.
