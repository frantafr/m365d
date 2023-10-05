# Sentinel - my cheat sheet
## Correlation of quarantine log events to get all details when monitoring
The customer use case is: *get an alert when a message is released from quarantine, providing also the name of the admin who performed the action.*
Actually it is not trivial as the EmailEvents and EmailPostDeliveryEvents M365D table do not contain the admin username information.
In addition, the qurantine log you can get from the compliance.microsoft.com portal (Audi Logs) is not available either in the OfficeActivity table that comes today (October 2023) with the Microsoft 365 native connector of Microsoft Sentinel.

So here is a way to fulfill this ask.

### Prequisites
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

### Final: create the right KQL query
Now you have the data, you are able to join the info from the different table.
Here is an example.
```
EmailPostDeliveryEvents
| where Action == "Quarantine release"
| extend NetworkMessageId_g=NetworkMessageId
| join (O365_CL | where Operation_s == "QuarantineReleaseMessage") on NetworkMessageId_g
| join (EmailEvents) on NetworkMessageId
| project TimeGenerated, ActionTrigger, ActionType, ActionResult, RecipientEmailAddress, AdminId=UserId_s, Operation_s, NetworkMessageId, Subject, SenderFromAddress, AuthenticationDetails, ConfidenceLevel
```
<img src="kql/kql%20release%20messages%20audit%20log.png" width="300" alt="KQL query to get full details of a quarantine release action" />

### What's next?
You can create an alert from this query, a report in a workbook or a full workflow depending on your needs!