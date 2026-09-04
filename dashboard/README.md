# Security Operations War Room
## Project AEGIS - Phase 12

React and TypeScript SOC interface providing real-time attack-path visualizations, risk metrics, live incident tracking, and containment approval controls.

### Architecture
- Frontend: React, TypeScript, Tailwind CSS.
- Backend: Amazon API Gateway (REST & WebSocket).
- Authentication: Amazon Cognito with mandatory MFA.
- Hosting: Amazon S3 static web hosting behind Amazon CloudFront with AWS WAF.
