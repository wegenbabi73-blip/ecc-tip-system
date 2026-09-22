# Security notes — V4
- V4 uses TOTP MFA with `otplib` and QR enrollment.
- MFA secrets are stored server-side; do not log them.
- Login with MFA uses a 5-minute pre-auth token, then issues the normal access token.
- Use HTTPS/TLS in deployment; do not expose SQLite directly.
- Set a strong random JWT_SECRET (32+ chars; preferably 64+ random bytes).
- Restrict CORS to trusted origins.
- Use a reverse proxy/WAF, backups, monitoring, OS hardening, and secret management for real deployment.
- The included UI is a starter and has not been independently security-certified.
