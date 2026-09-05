// What counts as an acceptable password. Until this existed the only rule
// was `z.string().min(8)`, which accepts "password".
//
// Deliberately *not* a character-class rule ("one upper, one digit, one
// symbol"). Those are well documented as counterproductive - they push
// people toward Password1! and a sticky note, and NIST's own guidance
// dropped them years ago. Length plus a rejection of the obvious is what
// actually helps.
const MIN_LENGTH = 12;

// The handful that show up at the top of every breach corpus, plus the
// ones this project invites specifically. Not a substitute for a real
// breach-corpus check - it is a floor, and it is honest about being one:
// the point is that "password", "porttorch" and "admin1234" are refused,
// not that everything weak is caught.
const OBVIOUS = [
  "password", "passwort", "12345678", "123456789", "1234567890", "qwertyuiop",
  "qwertzuiop", "letmein", "welcome", "iloveyou", "admin", "administrator",
  "changeme", "porttorch", "scanner", "monkey", "dragon", "sunshine", "princess",
  "football", "baseball", "trustno1", "starwars", "whatever", "superman",
];

export interface PasswordCheck {
  ok: boolean;
  // Says what is wrong and how to fix it, in one sentence, because the
  // person reading it is mid-task and the alternative is guessing.
  reason?: string;
}

/**
 * `username` is checked against the password because a password that
 * contains the account name is the single most guessable thing someone
 * picks when told "make it 12 characters" - and it is the one the
 * attacker already knows half of.
 */
export function checkPassword(password: string, username?: string): PasswordCheck {
  if (password.length < MIN_LENGTH) {
    return { ok: false, reason: `Use at least ${MIN_LENGTH} characters. Length matters more than symbols - a short passphrase of a few words beats a mangled word.` };
  }

  const lower = password.toLowerCase();

  // Whether `word` makes up most of the password, rather than merely
  // appearing in it. A plain `includes` is too blunt: "admin" is a
  // genuinely weak password and "Admin-Set-Passw0rd" is not, and a rule
  // that cannot tell them apart trains people to fight the rule instead
  // of picking better passwords. Non-alphanumerics are stripped first, so
  // "p-a-s-s-w-o-r-d" is not a way around this.
  const alphanumeric = lower.replace(/[^a-z0-9]/g, "");
  const dominates = (word: string): boolean => {
    if (!alphanumeric.includes(word)) return false;
    const remaining = alphanumeric.split(word).join("");
    return remaining.length < word.length;
  };

  for (const word of OBVIOUS) {
    if (dominates(word)) {
      return {
        ok: false,
        reason: `This is essentially "${word}", which is among the first things anyone guesses. Pick something unrelated to this tool or to common words.`,
      };
    }
  }

  if (username && username.length >= 3 && dominates(username.toLowerCase())) {
    return { ok: false, reason: "This is essentially the account name, which an attacker already knows. Pick something unrelated to it." };
  }

  // A single repeated character reaches any length requirement without
  // adding anything at all - "aaaaaaaaaaaa" is twelve characters and one
  // guess.
  if (new Set(password).size < 5) {
    return { ok: false, reason: "This uses too few distinct characters to be worth its length. Mix in more." };
  }

  // The same idea one level up: a repeated *unit* is only as strong as
  // the unit. "alice-alice-alice" has six distinct characters and
  // seventeen of length, and is one word to guess.
  if (isRepeatedUnit(alphanumeric)) {
    return { ok: false, reason: "This is one short piece repeated. Its length doesn't help - a guess only has to find the piece." };
  }

  return { ok: true };
}

// Whether `value` is some prefix repeated to fill its length. Only
// checks units short enough for the repetition to actually matter: two
// repeats of an eight-character word is not the weakness this is about.
function isRepeatedUnit(value: string): boolean {
  for (let unit = 1; unit <= Math.min(6, Math.floor(value.length / 2)); unit++) {
    if (value.length % unit !== 0) continue;
    const piece = value.slice(0, unit);
    if (piece.repeat(value.length / unit) === value) return true;
  }
  return false;
}

export const PASSWORD_MIN_LENGTH = MIN_LENGTH;
