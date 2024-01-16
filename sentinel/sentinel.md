# Sentinel - my cheat sheet
## Correlation of quarantine log events to get full monitoring details
The customer use case is: *get an alert when a message is released from quarantine, providing also the name of the admin who performed the action.*
Actually it is not trivial as the EmailEvents and EmailPostDeliveryEvents M365D tables do not contain the admin username information.
In addition, the quarantine log you can get from the compliance.microsoft.com portal (Audit Logs) is not available either in the OfficeActivity table that comes today (October 2023) with the Microsoft 365 native connector of Microsoft Sentinel.

UPDATE Jan 2024: there is another option, leveraging the CloudAppEvents table of Defender for Cloud Apps! If you have the product, this is the simplest way, so move to: https://github.com/frantafr/m365d/blob/main/xdr/xdr.md#interesting-advanced-hunting-queries-with-cloudappevents-table

Here is a way to fulfill this ask.

### Prerequisites
In Microsoft Sentinel, you have already connected M365 Defender and M365, using the native connectors:
- https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender?tabs=MDE
- https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/microsoft-365

Thanks to those connectors, you should be able to get logs from EmailEvents and OfficeActivity tables.
For example:
```
EmailEvents | take 10
```
and 
```
OfficeActivity | take 10
```

### Use the community Azure Function to get Audit.General logs from O365 Management API
See and follow https://github.com/Azure/Azure-Sentinel/tree/master/DataConnectors/O365%20Data

One personal tip: during the installation I hit an issue, the O365_CL table was not appearing while the Azure Function looked ok.
For troubleshooting, I went to "Log Stream" menu, there I grab the following error: 
```
2023-10-05T08:25:08Z   [Error]   EXCEPTION: MCASActivity-SecurityEvents: Invalid Login Endpoint Uri. Exception             :     Type    : Microsoft.PowerShell.Commands.WriteErrorException     Message : MCASActivity-SecurityEvents: Invalid Login Endpoint Uri.     HResult : -2146233087 CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,_TimerTrigger_ InvocationInfo        :     MyCommand        : _TimerTrigger_     ScriptLineNumber : 257     OffsetInLine     : 3     HistoryId        : 1     ScriptName       : C:\home\site\wwwroot\TimerTrigger\run.ps1     Line             : Write-Error -Message "MCASActivity-SecurityEvents: Invalid Login Endpoint Uri." -ErrorAction Stop                             PositionMessage  : At C:\home\site\wwwroot\TimerTrigger\run.ps1:257 char:3                        +         Write-Error -Message "MCASActivity-SecurityEvents: Invalid Lo …                        +         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~     PSScriptRoot     : C:\home\site\wwwroot\TimerTrigger     PSCommandPath    : C:\home\site\wwwroot\TimerTrigger\run.ps1     InvocationName   : _TimerTrigger_     CommandOrigin    : Internal ScriptStackTrace      : at <ScriptBlock>, C:\home\site\wwwroot\TimerTrigger\run.ps1: line 257

2023-10-05T08:25:08Z   [Error]   Executed 'Functions.TimerTrigger' (Failed, Id=85c42ab3-ca70-43d7-8eb9-4f7c1a18641e, Duration=8247ms)
```
Thanks to this message, and looking at the run.ps1 file, I understood there was an error with my LoginEndpoint variable. It was "https://login.microsoftonline.com/" while the script was expecting "https://login.microsoftonline.com"! Just one "/" was responsible of the error...

### Final: create the right KQL query
Now you have the data, you are able to join the info from the different table.
Here is an example. Here **I have both the details of the message released from quarantine as well as the admin name who performed the action!**
```
EmailPostDeliveryEvents
| where Action == "Quarantine release"
| extend NetworkMessageId_g=NetworkMessageId
| join (O365_CL | where Operation_s == "QuarantineReleaseMessage") on NetworkMessageId_g
| join (EmailEvents) on NetworkMessageId
| project TimeGenerated, ActionTrigger, ActionType, ActionResult, RecipientEmailAddress, AdminId=UserId_s, Operation_s, NetworkMessageId, Subject, SenderFromAddress, AuthenticationDetails, ConfidenceLevel
```
<img src="kql/kql%20release%20messages%20audit%20log.png" width="800" alt="KQL query to get full details of a quarantine release action" />

### What's next?
You can create an alert from this query, a report in a workbook or a full workflow depending on your needs!
