import bcrypt from "bcryptjs";

const SALT_ROUNDS = 12;

export function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

// A null hash is an SSO account, which has no local password: never a
// match, so the password login cannot be used to sign in as one.
export function verifyPassword(plain: string, hash: string | null): Promise<boolean> {
  if (hash === null) return Promise.resolve(false);
  return bcrypt.compare(plain, hash);
}
