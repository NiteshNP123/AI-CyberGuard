"""
AI CyberGuard — PostgreSQL Setup Script
========================================
Automates the full PostgreSQL database provisioning:
  1. Creates the 'cyberguard' database (idempotent)
  2. Creates the 'cyberguard_user' role with a secure password
  3. Runs scripts/db-migrate.sql to create all tables and indexes
  4. Verifies connectivity and prints the DATABASE_URL to set as env var

Usage:
  python scripts/setup-postgres.py --password <pg_superuser_password>

Defaults:
  --host       127.0.0.1
  --port       5432
  --superuser  postgres
  --db         cyberguard
  --appuser    cyberguard_user
  --apppass    cyberguard_app_secret
"""

import argparse
import os
import sys

try:
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
except ImportError:
    print("ERROR: psycopg2 not installed. Run: pip install psycopg2-binary")
    sys.exit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MIGRATION_FILE = os.path.join(SCRIPT_DIR, "db-migrate.sql")


def run(conn, sql, description=""):
    cur = conn.cursor()
    try:
        cur.execute(sql)
        print(f"  OK  {description or sql[:60]}")
    except psycopg2.errors.DuplicateDatabase:
        print(f"  SKIP (already exists): {description}")
        conn.rollback()
    except psycopg2.errors.DuplicateObject:
        print(f"  SKIP (already exists): {description}")
        conn.rollback()
    except Exception as e:
        print(f"  ERROR {description}: {e}")
        conn.rollback()
        raise
    finally:
        cur.close()


def main():
    parser = argparse.ArgumentParser(description="AI CyberGuard PostgreSQL setup")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--superuser", default="postgres")
    parser.add_argument("--password", required=True, help="PostgreSQL superuser password")
    parser.add_argument("--db", default="cyberguard")
    parser.add_argument("--appuser", default="cyberguard_user")
    parser.add_argument("--apppass", default="cyberguard_app_secret")
    args = parser.parse_args()

    print(f"\n=== AI CyberGuard PostgreSQL Setup ===")
    print(f"  Host:       {args.host}:{args.port}")
    print(f"  Superuser:  {args.superuser}")
    print(f"  Database:   {args.db}")
    print(f"  App user:   {args.appuser}\n")

    # Step 1: Connect as superuser to postgres db, create database and user
    try:
        conn_super = psycopg2.connect(
            host=args.host, port=args.port,
            user=args.superuser, password=args.password,
            database="postgres"
        )
        conn_super.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    except Exception as e:
        print(f"ERROR: Cannot connect to PostgreSQL as {args.superuser}: {e}")
        print("Make sure PostgreSQL is running on port 5432.")
        sys.exit(1)

    print("[1/4] Creating database and app user...")
    run(conn_super, f"CREATE DATABASE {args.db}", f"CREATE DATABASE {args.db}")
    run(conn_super,
        f"CREATE USER {args.appuser} WITH ENCRYPTED PASSWORD '{args.apppass}'",
        f"CREATE USER {args.appuser}")
    run(conn_super,
        f"GRANT ALL PRIVILEGES ON DATABASE {args.db} TO {args.appuser}",
        f"GRANT privileges to {args.appuser}")
    conn_super.close()

    # Step 2: Connect to the cyberguard database and run migration
    try:
        conn_db = psycopg2.connect(
            host=args.host, port=args.port,
            user=args.superuser, password=args.password,
            database=args.db
        )
        conn_db.autocommit = True
    except Exception as e:
        print(f"ERROR: Cannot connect to database {args.db}: {e}")
        sys.exit(1)

    print(f"\n[2/4] Running schema migration from {MIGRATION_FILE} ...")
    with open(MIGRATION_FILE, "r") as f:
        migration_sql = f.read()

    cur = conn_db.cursor()
    try:
        cur.execute(migration_sql)
        print("  OK  All tables and indexes created.")
    except Exception as e:
        print(f"  ERROR running migration: {e}")
        conn_db.close()
        sys.exit(1)
    finally:
        cur.close()

    # Step 3: Grant table privileges to appuser
    print(f"\n[3/4] Granting table privileges to {args.appuser} ...")
    cur = conn_db.cursor()
    try:
        cur.execute(f"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {args.appuser}")
        cur.execute(f"GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO {args.appuser}")
        print(f"  OK  Privileges granted.")
    except Exception as e:
        print(f"  ERROR granting privileges: {e}")
    finally:
        cur.close()
    conn_db.close()

    # Step 4: Verify connectivity with app user
    print(f"\n[4/4] Verifying connectivity as app user ({args.appuser}) ...")
    try:
        conn_verify = psycopg2.connect(
            host=args.host, port=args.port,
            user=args.appuser, password=args.apppass,
            database=args.db
        )
        cur = conn_verify.cursor()
        cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")
        tables = [row[0] for row in cur.fetchall()]
        cur.close()
        conn_verify.close()
        print(f"  OK  Connected. Tables present: {', '.join(tables)}")
    except Exception as e:
        print(f"  ERROR: {e}")
        sys.exit(1)

    db_url = f"postgresql://{args.appuser}:{args.apppass}@{args.host}:{args.port}/{args.db}"
    print(f"\n=== PostgreSQL Setup Complete ===")
    print(f"\nSet this environment variable before starting the API server:\n")
    print(f"  $env:DATABASE_URL = \"{db_url}\"")
    print(f"\nOr add to a .env file in the project root:\n")
    print(f"  DATABASE_URL={db_url}")


if __name__ == "__main__":
    main()
