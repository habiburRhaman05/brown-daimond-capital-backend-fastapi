-- Emailed links (verify email, invite, password reset) now hand the app a short-lived, single-use
-- "session_grant" instead of putting session tokens in the URL. Allow that token kind.
-- Safe to re-run.
ALTER TABLE auth_tokens DROP CONSTRAINT IF EXISTS auth_tokens_kind_check;
ALTER TABLE auth_tokens ADD CONSTRAINT auth_tokens_kind_check
  CHECK (kind IN ('refresh', 'verify_email', 'reset_password', 'invite', 'session_grant'));
