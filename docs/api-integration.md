# API Integration Documentation

Base URL: `http://localhost:8000/api/v1`

## Authentication
### Register Session
`POST /auth/register`

Request:
```json
{ "email": "john.doe@gmail.com", "name": "Demo User" }
```

## Scanning
### Text Scan
`POST /scan/text`

Request:
```json
{
  "user_email": "john.doe@gmail.com",
  "user_name": "Demo User",
  "content": "Contact john.doe@gmail.com at 555-123-4567"
}
```

### Image Scan (OCR)
`POST /scan/image` (multipart form-data)

Fields:
1. `user_email`
2. `user_name`
3. `image`

## Breach Intelligence
### Check Email
`POST /breach/check-email`

Request:
```json
{ "user_email": "john.doe@gmail.com" }
```

### Monitor Status
`GET /breach/monitor/status`

### Run Monitor Once
`POST /breach/monitor/run-once`

## Alerts
### List Alerts
`GET /alerts?email=john.doe@gmail.com`

### Acknowledge Alert
`POST /alerts/ack/{alert_id}`

### Realtime Alerts WebSocket
`WS /alerts/ws/{user_id}`

Payload example:
```json
{
  "type": "breach_monitor",
  "severity": "High",
  "title": "New Breach Event Detected",
  "message": "1 new breach events found for john.doe@gmail.com"
}
```

## Remediation
### Recommendations
`GET /remediation/recommendations?email=john.doe@gmail.com`

### Proactive Controls
`GET /remediation/proactive-controls?email=john.doe@gmail.com`

## Dashboard
### Summary
`GET /dashboard/summary?email=john.doe@gmail.com`

### Compliance
`GET /dashboard/compliance?email=john.doe@gmail.com`

## Error Handling
1. `400`: invalid input/no OCR text.
2. `404`: missing scan/risk/user.
3. `500`: unexpected server error.
