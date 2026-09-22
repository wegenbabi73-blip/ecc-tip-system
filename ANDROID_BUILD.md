# Android V5
1. Install Node.js + Android Studio + Android SDK on a build computer.
2. `npm install`
3. `npx cap add android`
4. `npx cap sync android`
5. `npx cap open android`
6. Generate a signed APK/AAB in Android Studio.
7. Do not commit signing keys or server secrets.
8. For a physical device, configure the app's API base to an HTTPS reachable server.

The public user flow is `public.html`; staff login is `login.html`.
