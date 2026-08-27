-- Development database seed for SalesCartCheckout.
-- This file intentionally contains no real credentials or production data.

PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS entity_type (
    id INTEGER PRIMARY KEY,
    entity VARCHAR(50) NOT NULL,
    description VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY,
    entity_type INTEGER NOT NULL,
    name VARCHAR(150) NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role VARCHAR(20) NOT NULL DEFAULT 'manager'
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    sku VARCHAR(50) NOT NULL UNIQUE,
    price NUMERIC(10,2) NOT NULL DEFAULT 0.00,
    stock_quantity INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    entity_id BIGINT NOT NULL,
    user_id BIGINT,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY,
    order_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    unit_price NUMERIC(10,2) NOT NULL
);

CREATE TABLE IF NOT EXISTS order_refunds (
    id INTEGER PRIMARY KEY,
    order_id INTEGER NOT NULL UNIQUE,
    refunded_by INTEGER,
    reason VARCHAR(255),
    amount NUMERIC(10,2) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS order_refund_items (
    id INTEGER PRIMARY KEY,
    refund_id INTEGER NOT NULL,
    order_item_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    unit_price NUMERIC(10,2) NOT NULL
);

INSERT OR IGNORE INTO entity_type (id, entity, description) VALUES
    (1, 'Customer', 'Sample customer account'),
    (2, 'Supplier', 'Sample supplier account');

INSERT OR IGNORE INTO entities (id, entity_type, name, email) VALUES
    (1, 1, 'Example Customer', 'customer@example.test'),
    (2, 2, 'Example Supplier', 'supplier@example.test');

INSERT OR IGNORE INTO products (id, name, sku, price, stock_quantity) VALUES
    (1, 'Demo Product', 'DEMO-001', 19.99, 25),
    (2, 'Sample Service', 'DEMO-002', 49.00, 10);

INSERT OR IGNORE INTO orders (id, entity_id, status) VALUES
    (1, 1, 'PENDING');

INSERT OR IGNORE INTO order_items (id, order_id, product_id, quantity, unit_price) VALUES
    (1, 1, 1, 2, 19.99);

COMMIT;
