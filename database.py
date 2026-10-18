import sqlite3
import re
from datetime import datetime
from pathlib import Path
import pymysql
from flask import current_app, g

BASE_DIR = Path(__file__).resolve().parent
ACTIVE_ENGINE = "sqlite"

def get_engine():
    global ACTIVE_ENGINE
    return ACTIVE_ENGINE

class UniversalCursor:
    """Normalizes query execution across SQLite and PyMySQL."""
    def __init__(self, raw_cursor, is_sqlite=False):
        self.cur = raw_cursor
        self.is_sqlite = is_sqlite

    def execute(self, sql, params=()):
        if self.is_sqlite:
            # Convert MySQL %s parameter syntax to SQLite ? syntax
            sql = re.sub(r'(?<!%)(%s)', '?', sql)
            sql = sql.replace('%%', '%')
            # Normalize MySQL date functions to SQLite syntax
            sql = re.sub(
                r'CURDATE\(\)\s*-\s*INTERVAL\s*\?\s*(?:DAY|DAYS)',
                "datetime('now', '-' || ? || ' days')",
                sql,
                flags=re.IGNORECASE
            )
            sql = re.sub(r'CURDATE\(\)', "date('now')", sql, flags=re.IGNORECASE)
            sql = re.sub(r'NOW\(\)', "datetime('now')", sql, flags=re.IGNORECASE)
        self.cur.execute(sql, params)
        return self

    def fetchall(self):
        rows = self.cur.fetchall()
        if self.is_sqlite:
            return [dict(r) for r in rows]
        return rows

    def fetchone(self):
        row = self.cur.fetchone()
        if self.is_sqlite and row is not None:
            return dict(row)
        return row

    @property
    def lastrowid(self):
        return self.cur.lastrowid

    @property
    def rowcount(self):
        return self.cur.rowcount

class UniversalDB:
    def __init__(self, conn, is_sqlite=False):
        self.conn = conn
        self.is_sqlite = is_sqlite

    def cursor(self):
        if self.is_sqlite:
            self.conn.row_factory = sqlite3.Row
            return UniversalCursor(self.conn.cursor(), is_sqlite=True)
        return UniversalCursor(self.conn.cursor(), is_sqlite=False)

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()

def _sqlite_curdate():
    return datetime.now().strftime("%Y-%m-%d")

def _sqlite_now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_db():
    if "db" not in g:
        cfg = current_app.config
        if ACTIVE_ENGINE == "mysql":
            conn = pymysql.connect(
                host=cfg["DB_HOST"], port=cfg["DB_PORT"],
                user=cfg["DB_USER"], password=cfg["DB_PASSWORD"],
                database=cfg["DB_NAME"], charset="utf8mb4",
                autocommit=False, cursorclass=pymysql.cursors.DictCursor
            )
            g.db = UniversalDB(conn, is_sqlite=False)
        else:
            conn = sqlite3.connect(cfg["SQLITE_PATH"])
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.create_function("CURDATE", 0, _sqlite_curdate)
            conn.create_function("NOW", 0, _sqlite_now)
            g.db = UniversalDB(conn, is_sqlite=True)
    return g.db

def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        try:
            if exc is None:
                db.commit()
            else:
                db.rollback()
        finally:
            db.close()

def query_all(sql, params=()):
    db = get_db()
    cur = db.cursor()
    cur.execute(sql, params)
    return cur.fetchall()

def query_one(sql, params=()):
    db = get_db()
    cur = db.cursor()
    cur.execute(sql, params)
    return cur.fetchone()

def initialize_database(cfg):
    global ACTIVE_ENGINE
    if cfg.DB_ENGINE == "mysql":
        try:
            conn = pymysql.connect(
                host=cfg.DB_HOST, port=cfg.DB_PORT, user=cfg.DB_USER,
                password=cfg.DB_PASSWORD, charset="utf8mb4", autocommit=True
            )
            with conn.cursor() as cur:
                cur.execute(f"CREATE DATABASE IF NOT EXISTS `{cfg.DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
            conn.select_db(cfg.DB_NAME)
            with conn.cursor() as cur:
                _create_mysql_tables(cur)
            conn.close()
            ACTIVE_ENGINE = "mysql"
            return "MySQL (Production)"
        except Exception as e:
            print(f"[LinkPulse DB Notice] MySQL connection failed ({e}). Defaulting to SQLite.")

    # SQLite Fallback
    ACTIVE_ENGINE = "sqlite"
    conn = sqlite3.connect(cfg.SQLITE_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    _create_sqlite_tables(conn)
    conn.close()
    return "SQLite (Embedded Zero-Config)"

def _create_sqlite_tables(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS campaigns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        tag TEXT NOT NULL UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        original_url TEXT NOT NULL,
        short_code TEXT NOT NULL UNIQUE,
        custom_alias TEXT UNIQUE,
        campaign_id INTEGER NULL REFERENCES campaigns(id) ON DELETE SET NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NULL,
        click_limit INTEGER NULL,
        click_count INTEGER NOT NULL DEFAULT 0,
        password_hash TEXT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'expired'))
    );

    CREATE TABLE IF NOT EXISTS click_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        link_id INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
        clicked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        referrer TEXT NULL,
        user_agent TEXT NULL,
        device_type TEXT NOT NULL DEFAULT 'desktop',
        browser TEXT NULL,
        ip_hash TEXT NULL,
        is_bot INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_links_short_code ON links(short_code);
    CREATE INDEX IF NOT EXISTS idx_clicks_link_id ON click_events(link_id);
    CREATE INDEX IF NOT EXISTS idx_clicks_time ON click_events(clicked_at);
    """)
    conn.commit()

def _create_mysql_tables(cur):
    cur.execute("""
    CREATE TABLE IF NOT EXISTS campaigns (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(120) NOT NULL UNIQUE,
        tag VARCHAR(60) NOT NULL UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS links (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(160) NOT NULL,
        original_url VARCHAR(2048) NOT NULL,
        short_code VARCHAR(64) NOT NULL UNIQUE,
        custom_alias VARCHAR(64) UNIQUE,
        campaign_id INT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NULL,
        click_limit INT NULL,
        click_count INT NOT NULL DEFAULT 0,
        password_hash VARCHAR(255) NULL,
        status ENUM('active', 'disabled', 'expired') NOT NULL DEFAULT 'active',
        FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS click_events (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        link_id INT NOT NULL,
        clicked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        referrer VARCHAR(255) NULL,
        user_agent VARCHAR(512) NULL,
        device_type VARCHAR(32) NOT NULL DEFAULT 'desktop',
        browser VARCHAR(64) NULL,
        ip_hash VARCHAR(64) NULL,
        is_bot TINYINT(1) NOT NULL DEFAULT 0,
        FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)