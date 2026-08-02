import { db } from "../src/db";
import { hashPassword } from "../src/auth/password";

async function main() {
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;
  if (!username || !password) {
    console.log("ADMIN_USERNAME/ADMIN_PASSWORD not set, skipping admin seed");
    return;
  }

  const passwordHash = await hashPassword(password);
  await db
    .insertInto("users")
    .values({ username, password_hash: passwordHash, role: "admin" })
    .onConflict((oc) => oc.column("username").doUpdateSet({ password_hash: passwordHash }))
    .execute();

  console.log(`Admin user "${username}" ready`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => db.destroy());
