import { describe, expect, it } from "vitest";
import { checkPassword, PASSWORD_MIN_LENGTH } from "./passwordPolicy";

describe("checkPassword", () => {
  it("accepts a passphrase", () => {
    expect(checkPassword("correct horse battery staple").ok).toBe(true);
    expect(checkPassword("Tr0ub4dor-and-a-half").ok).toBe(true);
  });

  it("rejects anything shorter than the minimum", () => {
    const result = checkPassword("short1!");
    expect(result.ok).toBe(false);
    expect(result.reason).toContain(String(PASSWORD_MIN_LENGTH));
  });

  it("rejects a password that is essentially one obvious word, even when long enough", () => {
    // Every one of these clears 12 characters, which is exactly why a
    // length rule alone is not enough.
    for (const bad of ["passwordpassword", "password-2026", "administrator99", "changeme12345", "p-a-s-s-w-o-r-d-1"]) {
      const result = checkPassword(bad);
      expect(result.ok, `${bad} should be rejected`).toBe(false);
      expect(result.reason).toBeTruthy();
    }
  });

  it("allows an obvious word that is only a small part of a real passphrase", () => {
    // The rule has to tell "admin" from "Admin-Set-Passw0rd". One is a
    // guess; the other is a password that happens to contain five common
    // letters, and rejecting it trains people to fight the rule rather
    // than pick better passwords.
    for (const fine of ["Admin-Set-Passw0rd", "the-admin-rides-a-bicycle", "welcome-to-the-jungle-77"]) {
      const result = checkPassword(fine);
      expect(result.ok, `${fine} should be accepted (${result.reason ?? ""})`).toBe(true);
    }
  });

  it("rejects a password that is essentially the account name", () => {
    const result = checkPassword("alice-alice-alice", "alice");
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("account name");
    // The same rule is about the pairing, not the string: for someone
    // else this is just a repeated word, caught by the distinct-character
    // rule instead - either way it is refused, for the right reason.
    expect(checkPassword("alice-alice-alice", "bob").ok).toBe(false);
  });

  it("allows a real passphrase that happens to contain the account name", () => {
    // A password is not weak because the person is called Alice. Refusing
    // this would be the same over-reach as refusing "Admin-Set-Passw0rd".
    expect(checkPassword("alice-in-wonderland-2026", "alice").ok).toBe(true);
  });

  it("ignores a very short username rather than rejecting half the alphabet", () => {
    // A two-character username would otherwise reject any password
    // containing those two letters in sequence.
    expect(checkPassword("thequickbrownfox", "th").ok).toBe(true);
  });

  it("rejects length made of repetition", () => {
    const result = checkPassword("aaaaaaaaaaaaaaaa");
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("distinct");
  });

  it("is case-insensitive about the obvious ones", () => {
    expect(checkPassword("PASSWORD1234").ok).toBe(false);
    expect(checkPassword("ChangeMe1234").ok).toBe(false);
  });
});
