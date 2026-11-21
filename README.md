# Stormy License Server

FastAPI license API for Stormy Tweaks.

## Deploy on Render

1. Push these files to a GitHub repository.
2. In Render choose **New + → Blueprint** and select this repository.
3. Review the resources and deploy.
4. Open the created web service. Its URL is your API base URL.
5. In Render → service → Environment, copy the generated `ADMIN_SECRET` and store it privately. Never put it in the desktop app or publish it.
6. Test `https://YOUR-SERVICE.onrender.com/health`.

## Admin: create a key

Send a POST request to `/admin/keys` with header `X-Admin-Secret: YOUR_ADMIN_SECRET` and JSON body:
```json
{"duration_days":30,"label":"Customer"}
```
Use `duration_days: null` for lifetime.

Revoke a key with POST `/admin/revoke?license_key=THE_KEY` and the same admin header.

## Client integration

The desktop app sends the key and a stable, privacy-conscious device identifier to `/activate`, then stores the returned token securely. It periodically calls `/verify`. Do not embed `ADMIN_SECRET` or `TOKEN_SECRET` in the desktop app.

This is a starter license service, not unbreakable DRM. HWID binding can lock out legitimate users after hardware changes; provide a manual reset process. Use HTTPS only.
