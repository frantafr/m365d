# Defender XDR - my cheat sheet
## Interesting advanced hunting queries with CloudAppEvents table
- Admins accessing emails? Which emails 📧?
```
CloudAppEvents
| where ActionType == "AdminMailAccess"
| extend extProperties = parse_json(parse_json(RawEventData)).ExtendedProperties
| mv-apply extProperties on (
    where tostring(extProperties.Name) == "InternetMessageId" | project InternetMessageId = url_decode(tostring(extProperties.Value))
  )
| join EmailEvents on InternetMessageId
| project Timestamp, ActionType, InternetMessageId, AdminName = AccountDisplayName, SenderFromAddress, RecipientEmailAddress, Subject, ReportId
```

- Admins releasing messages from quarantine? which admins 👮‍♂️ and which emails?
```
CloudAppEvents
| where ActionType == "QuarantineReleaseMessage"
| project Timestamp, AccountDisplayName, ActionType, NetworkMessageId=tostring(RawEventData.NetworkMessageId)
| join EmailPostDeliveryEvents on NetworkMessageId
| join EmailEvents on NetworkMessageId
| project Timestamp, ActionType, NetworkMessageId, AdminName = AccountDisplayName, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, LatestDeliveryAction, LatestDeliveryLocation, ThreatTypes1, ReportId
```