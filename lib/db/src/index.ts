import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

let pool: pg.Pool | null = null;
let dbInstance: NodePgDatabase<typeof schema> | null = null;

if (process.env.DATABASE_URL) {
  try {
    pool = new Pool({ connectionString: process.env.DATABASE_URL });
    dbInstance = drizzle(pool, { schema });
  } catch (err) {
    console.warn("Could not connect to PostgreSQL via DATABASE_URL, using fallback store:", err);
  }
}

export const db = dbInstance;
export { pool };
export * from "./schema";
