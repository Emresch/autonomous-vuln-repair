from app import init_catalog_db, search_products_by_category, format_currency

def test_normal_category_search():
    conn = init_catalog_db()
    rows = search_products_by_category(conn, "electronics", 1500.0)
    assert len(rows) == 2
    assert rows[0][1] == "Laptop"

def test_price_filter_and_helper():
    conn = init_catalog_db()
    rows = search_products_by_category(conn, "electronics", 50.0)
    assert len(rows) == 1
    assert rows[0][1] == "Mouse"
    assert format_currency(25.0) == "$25.00"
