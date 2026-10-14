import { createPostgresDb } from "../src/db.js";

// Applies pending migrations to DATABASE_URL and exits. The server also migrates on start;
// run this as a separate release step when you prefer schema changes before the rollout.
const url = process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL is required");
  process.exit(1);
}
const db = await createPostgresDb(url, 1);
await db.close();
console.log("migrations applied");
