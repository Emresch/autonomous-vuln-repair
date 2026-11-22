from app import init_catalog_db, search_products_by_category

def test_sqli_union_and_tautology_blocked():
    conn = init_catalog_db()
    payload = "electronics' OR '1'='1' --"
    rows = search_products_by_category(conn, payload, 50.0)
    assert rows == [], f"SQLi exploit returned unauthorized rows: {rows}"
