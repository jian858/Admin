# Murmur Admin Firebase Authentication rollout

## Branch changes

The repair branch switches the Admin browser login from Supabase password auth
to Firebase Authentication for project `murmur-fc430`. The browser sends a
Firebase ID token to the Admin Edge Function. The browser does not determine
administrator status.

The Edge Function source is now included at:

`supabase/functions/murmur-admin-supabase/index.ts`

It verifies the Firebase token signature, issuer, audience and verified email,
then checks the enabled `super_admin` row in `public.murmur_admin_allowlist`.
It uses the allowlist's existing Supabase `user_id` for audit records and
admin database operations.

## Required review before production

1. Confirm the allowlist email is the verified Firebase email for the intended
   administrator and that the row is enabled with role `super_admin`.
2. Confirm the allowlist `user_id` still references the correct existing
   Supabase auth user. It remains the audit actor ID for compatibility.
3. Review the complete Edge Function diff and run Deno type checking.
4. Deploy the Edge Function only after the frontend and function are ready
   together. Deploying only one side will temporarily break Admin requests.
5. Test a valid admin Firebase account, a non-admin Firebase account, an
   unverified email, an expired token, every dashboard read, and every write.
6. Verify admin audit rows and check the previous SQLSTATE 25006 issue using
   the real action that originally failed.
7. Do not remove the old Supabase Auth user or allowlist row until the Firebase
   flow is proven in production.

## Security notes

- Firebase web configuration and the Supabase publishable key are public
  client configuration, not secrets.
- The Supabase service-role key remains server-side in Edge Function secrets.
- The allowlist is checked on every privileged request.
- The Firebase token's email must be verified.
- Client-side email checks are only a convenience; server authorization is
  authoritative.
- Admin stays a separate website and GitHub repository.
