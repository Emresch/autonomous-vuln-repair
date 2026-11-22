import sqlite3
from typing import List, Tuple

def init_catalog_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL, secret_cost REAL)")
    cur.execute("INSERT INTO products VALUES (1, 'Laptop', 'electronics', 1200.0, 700.0)")
    cur.execute("INSERT INTO products VALUES (2, 'Mouse', 'electronics', 25.0, 8.0)")
    cur.execute("INSERT INTO products VALUES (3, 'Desk', 'furniture', 300.0, 150.0)")
    conn.commit()
    return conn

def format_currency(amount: float) -> str:
    return f"${amount:.2f}"

def search_products_by_category(conn: sqlite3.Connection, category: str, max_price: float) -> List[Tuple]:
    cursor = conn.cursor()
    sql = f"SELECT id, name, price FROM products WHERE category = '{category}' AND price <= {max_price}"
    cursor.execute(sql)
    return cursor.fetchall()
