-- Sprint 2.2 Review & Updates, section 6: our team's own reference number(s) per client.
-- The client never sees or sets these; a client can have more than one, each edited on its own.
CREATE TABLE client_numbers (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id   UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  number      TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_client_numbers_client ON client_numbers (client_id, created_at);

ALTER TABLE client_numbers ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON client_numbers FROM anon, authenticated;
