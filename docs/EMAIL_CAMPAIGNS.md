# Murmur Admin email campaigns

The Admin dashboard includes an **Email Campaigns** tab. It sends one individualized message per recipient through Resend from the server-side Supabase Edge Function.

## Required secrets

Set these as Supabase Edge Function secrets for the `murmur-admin-supabase` function:

- `RESEND_API_KEY`: a Resend API key. Never put this key in frontend code, GitHub, or a public environment variable.
- `RESEND_FROM_EMAIL`: a sender identity on a domain verified in Resend, for example `Murmur <updates@example.com>`. Replace the example with a verified address on a domain you control.

The function already uses the Supabase service-role key on the server. Do not expose it to the browser.

## Current scope and important limitation

- The recipient source is Supabase Auth's admin user list.
- Only accounts with a confirmed email are included.
- Firebase-only accounts that are not mirrored into Supabase Auth are **not** included. Murmur's Firebase-first identity architecture has previously had missing Supabase Auth/profile rows, so verify recipient coverage against Firebase Auth before describing this as an all-user mailing list.
- The tool is intended for essential service, safety, account, and product announcements. Do not use it for promotional marketing. Add explicit marketing consent and unsubscribe handling before introducing promotional campaigns.
- The UI previews the recipient count and requires a second confirmation before sending.
- The backend sends batches of up to 100 individualized messages. It uses Resend `Idempotency-Key` values per campaign batch to make retries safer.
- The result reports Resend API acceptance, not final inbox delivery. Configure and verify Resend webhooks separately if delivery, bounce, complaint, or suppression reporting is required.
- Campaign history is written to the existing `admin_audit_log`; recipient email addresses and message bodies are not written there.

## Deployment and test checklist

1. Verify the sending domain in Resend.
2. Add `RESEND_API_KEY` and `RESEND_FROM_EMAIL` to Supabase Edge Function secrets.
3. Deploy the updated `murmur-admin-supabase` Edge Function and Admin frontend together. The current PR remains a draft and is not deployed.
4. Test with a small set of verified test accounts first.
5. Confirm the preview count, sender, message formatting, audit entry, Resend acceptance, and actual inbox delivery.
6. Verify Firebase Auth and Supabase Auth recipient parity before using the tool for every Murmur user.
