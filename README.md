# FRAMECUT License API + Discord Webhook (no Discord bot token)

This service preserves the existing `FC1.<base64url(payload)>.<base64url(RSA-SHA256 signature)>` license format and the `FCR1` signed revocation-list format. It does not need a Discord bot token, Discord client ID, or guild ID.

## Before deploying

- Keep the same Render service and its existing persistent disk mounted at `/var/data` whenever possible. Do not delete the disk or change the `DATA_FILE` path, or existing server-side license records may be lost.
- Set `LICENSE_PRIVATE_XML` to the exact existing RSA private XML matching the public key embedded in the current license verifier. Never commit it to GitHub or put it in the customer app.
- Set `ADMIN_API_TOKEN` to the same long random secret configured in the seller-only PowerShell generator.
- Create a NEW Discord webhook in the target channel and set `DISCORD_WEBHOOK_URL`. Keep its URL private; rotate any webhook URL previously exposed.
- This API does not require `DISCORD_BOT_TOKEN`, `DISCORD_CLIENT_ID`, or `DISCORD_GUILD_ID`.

## Endpoints

- `GET /health` — health check; indicates whether a webhook is configured.
- `GET /revoked_list.txt` — signed FCR1 revocation list for existing clients.
- `POST /api/license/issue` — issue a signed FC1 key; requires `Authorization: Bearer <ADMIN_API_TOKEN>`.
- `POST /api/license/revoke` — revoke a license by its SHA-256 payload ID.
- `POST /api/license/restore` — restore a license by ID.
- `GET /api/license/status/:id` — check status (authenticated).

Webhook notifications are best-effort and do not determine whether an API operation succeeds. Slash commands are intentionally not supported in this webhook-only setup.
