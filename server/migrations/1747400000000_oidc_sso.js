/* eslint-disable */
exports.shorthands = undefined;

// Single sign-on over OpenID Connect (auth/oidc.ts).
//
// app_settings.oidc_*: the provider, configured from the Settings page like
// SMTP and HEC. The client secret is withheld from the settings API the
// same way smtp_password is. Group lists map the provider's group claim
// onto the three dashboard roles, highest match wins;
// oidc_default_role decides what a user in none of them gets - NULL means
// they are refused, which is the safe default for a recon platform.
//
// users: an SSO account is identified by (issuer, subject), never by its
// name - names can be reassigned at the provider, subjects cannot. Its
// password_hash is NULL, which the password login refuses, so a local
// password can never be used to sign in as an SSO user.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      ADD COLUMN oidc_enabled boolean NOT NULL DEFAULT false,
      ADD COLUMN oidc_issuer_url text,
      ADD COLUMN oidc_client_id text,
      ADD COLUMN oidc_client_secret text,
      ADD COLUMN oidc_redirect_uri text,
      ADD COLUMN oidc_scopes text NOT NULL DEFAULT 'openid profile email',
      ADD COLUMN oidc_username_claim text NOT NULL DEFAULT 'preferred_username',
      ADD COLUMN oidc_groups_claim text NOT NULL DEFAULT 'groups',
      ADD COLUMN oidc_admin_groups text[] NOT NULL DEFAULT '{}',
      ADD COLUMN oidc_operator_groups text[] NOT NULL DEFAULT '{}',
      ADD COLUMN oidc_user_groups text[] NOT NULL DEFAULT '{}',
      ADD COLUMN oidc_default_role text CHECK (oidc_default_role IN ('user', 'operator')),
      ADD COLUMN oidc_button_label text NOT NULL DEFAULT 'Sign in with SSO';

    ALTER TABLE users
      ALTER COLUMN password_hash DROP NOT NULL,
      ADD COLUMN auth_source text NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'oidc')),
      ADD COLUMN oidc_issuer text,
      ADD COLUMN oidc_subject text,
      ADD CONSTRAINT users_oidc_identity_check CHECK (
        (auth_source = 'local' AND oidc_subject IS NULL AND password_hash IS NOT NULL)
        OR (auth_source = 'oidc' AND oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL)
      );
    CREATE UNIQUE INDEX users_oidc_identity_unique ON users (oidc_issuer, oidc_subject) WHERE auth_source = 'oidc';
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DELETE FROM users WHERE auth_source = 'oidc';
    DROP INDEX users_oidc_identity_unique;
    ALTER TABLE users
      DROP CONSTRAINT users_oidc_identity_check,
      DROP COLUMN oidc_subject,
      DROP COLUMN oidc_issuer,
      DROP COLUMN auth_source,
      ALTER COLUMN password_hash SET NOT NULL;
    ALTER TABLE app_settings
      DROP COLUMN oidc_button_label,
      DROP COLUMN oidc_default_role,
      DROP COLUMN oidc_user_groups,
      DROP COLUMN oidc_operator_groups,
      DROP COLUMN oidc_admin_groups,
      DROP COLUMN oidc_groups_claim,
      DROP COLUMN oidc_username_claim,
      DROP COLUMN oidc_scopes,
      DROP COLUMN oidc_redirect_uri,
      DROP COLUMN oidc_client_secret,
      DROP COLUMN oidc_client_id,
      DROP COLUMN oidc_issuer_url,
      DROP COLUMN oidc_enabled;
  `);
};
