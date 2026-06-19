# API Key Rotation Runbook

## Rotation Schedule (PCI DSS Req 3.7 + Mastercard §3.2)
| Key Type         | Rotation Interval | Owner        |
|-----------------|-------------------|--------------|
| API keys (write) | 90 days           | Engineering  |
| API keys (read)  | 180 days          | Engineering  |
| ENCRYPTION_KEY   | 365 days          | Security     |
| BOOTSTRAP_TOKEN  | After first use   | Engineering  |

## Rotation Procedure for API Keys
1. POST /v1/admin/api-keys/{id}/rotate — generates new key, revokes old
2. Update caller with new key (secure channel: 1Password / Vault)
3. Verify old key returns 401 within 5 minutes
4. Log rotation event to audit log (automatic via audit middleware)

## ENCRYPTION_KEY Rotation (requires DB re-encryption)
1. Set NEW_ENCRYPTION_KEY in Fly.io secrets alongside ENCRYPTION_KEY
2. Run migration script: reads with old key, writes with new key
3. Remove old ENCRYPTION_KEY from secrets
4. Verify decryption works on sample rows

## Dual-Control Requirements
- Key creation: requires BOOTSTRAP_TOKEN (separate channel) OR write-scope key
- Key revocation: requires write-scope key — log actor via audit middleware
- ENCRYPTION_KEY change: requires 2 engineers (one sets secret, one verifies)
