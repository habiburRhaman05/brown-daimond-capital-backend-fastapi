-- BDCap Client Portal: business schema (custom-JWT auth lives in profiles + auth_tokens).
-- Safe to re-run: drops everything this file creates, then rebuilds it.
-- WARNING: re-running deletes all data in these tables.

DROP TABLE IF EXISTS audit_log              CASCADE;
DROP TABLE IF EXISTS signup_requests        CASCADE;
DROP TABLE IF EXISTS invites                CASCADE;
DROP TABLE IF EXISTS change_request_events  CASCADE;
DROP TABLE IF EXISTS change_requests        CASCADE;
DROP TABLE IF EXISTS portal_status          CASCADE;
DROP TABLE IF EXISTS site_config_history    CASCADE;
DROP TABLE IF EXISTS site_configs           CASCADE;
DROP TABLE IF EXISTS client_details         CASCADE;
DROP TABLE IF EXISTS auth_tokens            CASCADE;
DROP TABLE IF EXISTS org_memberships        CASCADE;
DROP TABLE IF EXISTS organizations          CASCADE;
DROP TABLE IF EXISTS profiles               CASCADE;

DROP TYPE IF EXISTS signup_status          CASCADE;
DROP TYPE IF EXISTS invite_status          CASCADE;
DROP TYPE IF EXISTS change_request_status  CASCADE;
DROP TYPE IF EXISTS user_role              CASCADE;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- PROFILES: one row per person who can sign in
-- ============================================================
CREATE TABLE profiles (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email              TEXT NOT NULL,
  full_name          TEXT NOT NULL DEFAULT '',
  password_hash      TEXT,                         -- NULL until an invited user sets a password
  role               TEXT NOT NULL DEFAULT 'client' CHECK (role IN ('admin', 'staff', 'client')),
  email_verified_at  TIMESTAMPTZ,
  is_active          BOOLEAN NOT NULL DEFAULT true,
  last_login_at      TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT profiles_email_lower CHECK (email = lower(email))
);
CREATE UNIQUE INDEX uq_profiles_email ON profiles (email);
CREATE INDEX idx_profiles_role ON profiles (role, created_at DESC);

-- ============================================================
-- AUTH TOKENS: refresh sessions + one-time email links (only SHA-256 hashes are stored)
-- ============================================================
CREATE TABLE auth_tokens (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL CHECK (kind IN ('refresh', 'verify_email', 'reset_password', 'invite')),
  token_hash  TEXT NOT NULL UNIQUE,
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_auth_tokens_user_kind ON auth_tokens (user_id, kind);
CREATE INDEX idx_auth_tokens_expiry ON auth_tokens (expires_at);

-- ============================================================
-- CLIENT DETAILS: everything the client enters in the portal (one row per client)
-- ============================================================
CREATE TABLE client_details (
  user_id             UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,

  -- About you
  legal_first_name    TEXT,
  legal_last_name     TEXT,
  date_of_birth       DATE,
  personal_email      TEXT,
  personal_phone      TEXT,
  preferred_contact   TEXT,
  contact_time        JSONB NOT NULL DEFAULT '[]'::jsonb,   -- ["Morning","Evening","Night"]
  mailing_street      TEXT,
  mailing_city        TEXT,
  mailing_state       TEXT,
  mailing_zip         TEXT,

  -- Your team (up to five rows: role, name, email, phone, relationship)
  team_members        JSONB NOT NULL DEFAULT '[]'::jsonb,

  -- About your business
  business_name       TEXT,
  backup_name_1       TEXT,
  backup_name_2       TEXT,
  business_theme      TEXT,
  purpose_text        TEXT,
  naics_code          TEXT,
  sic_code            TEXT,

  -- Your website (copy answers; the design itself is in site_configs)
  domain_name         TEXT,
  tagline             TEXT,
  cta_text            TEXT,

  -- Every other portal answer, kept as sent so nothing the page collects is ever dropped
  raw_fields          JSONB NOT NULL DEFAULT '{}'::jsonb,

  -- Portal lifecycle (server-owned; a client can never write these)
  completed_on        TIMESTAMPTZ,
  locked_on           TIMESTAMPTZ,
  changes_until       TIMESTAMPTZ,

  -- Set by our team once the site is built
  site_preview_url    TEXT,
  site_deployed_on    DATE,
  site_url            TEXT,
  client_number       TEXT,

  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- SITE CONFIG: the website design the client picked, stored exactly as the page sent it
-- ============================================================
CREATE TABLE site_configs (
  client_id     UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
  config_data   JSONB NOT NULL DEFAULT '{}'::jsonb,   -- queryable copy
  config_raw    TEXT,                                   -- the request body, untouched
  version       INTEGER NOT NULL DEFAULT 1,
  updated_by    UUID REFERENCES profiles(id),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE site_config_history (
  id            BIGSERIAL PRIMARY KEY,
  client_id     UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  version       INTEGER NOT NULL,
  config_data   JSONB NOT NULL,
  config_raw    TEXT,
  changed_by    UUID REFERENCES profiles(id),
  changed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_site_history_client ON site_config_history (client_id, version DESC);

-- ============================================================
-- CHANGE REQUESTS: PENDING <-> RESOLVED, switchable both ways
-- ============================================================
CREATE TABLE change_requests (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id    UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  part         TEXT NOT NULL CHECK (part IN ('website', 'team', 'you', 'business')),
  text         TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'resolved')),
  admin_note   TEXT,
  resolved_by  UUID REFERENCES profiles(id),
  resolved_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_change_requests_client ON change_requests (client_id, created_at DESC);
CREATE INDEX idx_change_requests_status ON change_requests (status, created_at DESC);

-- ============================================================
-- INVITES + SIGNUP REQUESTS
-- ============================================================
CREATE TABLE invites (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email        TEXT NOT NULL CHECK (email = lower(email)),
  status       TEXT NOT NULL DEFAULT 'sent' CHECK (status IN ('sent', 'accepted', 'revoked')),
  invited_by   UUID REFERENCES profiles(id),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  accepted_at  TIMESTAMPTZ
);
CREATE INDEX idx_invites_email ON invites (email, created_at DESC);

CREATE TABLE signup_requests (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email        TEXT NOT NULL CHECK (email = lower(email)),
  full_name    TEXT,
  company      TEXT,
  phone        TEXT,
  message      TEXT,
  status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  admin_note   TEXT,
  decided_by   UUID REFERENCES profiles(id),
  decided_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_signup_requests_status ON signup_requests (status, created_at DESC);
CREATE UNIQUE INDEX uq_signup_requests_open ON signup_requests (email) WHERE status = 'pending';

-- ============================================================
-- AUDIT LOG
-- ============================================================
CREATE TABLE audit_log (
  id          BIGSERIAL PRIMARY KEY,
  actor_id    UUID REFERENCES profiles(id) ON DELETE SET NULL,
  action      TEXT NOT NULL,
  client_id   UUID REFERENCES profiles(id) ON DELETE CASCADE,
  meta        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_client ON audit_log (client_id, created_at DESC);
CREATE INDEX idx_audit_created ON audit_log (created_at DESC);

-- ============================================================
-- ROW-LEVEL SECURITY: on for every table, with no policies. Supabase's public REST API
-- (anon / authenticated keys) can therefore read and write nothing; only this backend,
-- connecting as the database owner, can.
-- ============================================================
ALTER TABLE profiles             ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_tokens          ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_details       ENABLE ROW LEVEL SECURITY;
ALTER TABLE site_configs         ENABLE ROW LEVEL SECURITY;
ALTER TABLE site_config_history  ENABLE ROW LEVEL SECURITY;
ALTER TABLE change_requests      ENABLE ROW LEVEL SECURITY;
ALTER TABLE invites              ENABLE ROW LEVEL SECURITY;
ALTER TABLE signup_requests      ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log            ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;
