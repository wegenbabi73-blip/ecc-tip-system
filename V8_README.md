# ECC Tip & Information Management System — V8

This package combines the V7 control-center build with production-oriented hardening fixes.

## Included
- Capacitor Android wrapper
- Public tip portal connected to the backend
- Offline queue for text-only submissions
- JWT authentication
- TOTP MFA
- Admin/supervisor/analyst/officer roles
- Tip assignment, status/risk updates and case history
- Reports and CSV export
- Authenticated attachment download
- Rate limiting and Helmet
- SQLite database for the starter deployment

## Important
This remains a development/starter system, not a security-certified government production system.
Before production use, add HTTPS/TLS, managed secrets, approved CORS origins, malware scanning and content validation for uploads, encrypted backups, centralized logging/monitoring, penetration testing, incident response, and approved organizational policies.

## Setup
1. Install Node.js and JDK 17.
2. Run `npm install`.
3. Run `npm run install:all`.
4. Copy `server/.env.example` to `server/.env` and set a strong random `JWT_SECRET`, database path, upload path and trusted CORS origins.
5. Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` in the environment and run:
   `node server/create-admin.js`
6. Start the backend with `npm run server`.
7. For Android:
   `npx cap add android`
   `npx cap sync android`
   `npx cap open android`

For an Android emulator the default API endpoint is `http://10.0.2.2:8080/api`.
For a physical phone, set the API base using browser/dev tooling or replace the default with the reachable HTTPS backend URL.

## Build
In Android Studio: Build → Generate App Bundles or APKs.
