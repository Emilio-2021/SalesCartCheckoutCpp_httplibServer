# SalesCartCheckout

SalesCartCheckout is a C++17 shopping-cart and checkout demonstration with a public storefront and a separate internal management workspace.

## Features

- Guest browsing, cart management, checkout, and simulated payment
- Atomic order creation with inventory decrementing
- Order confirmation for the completing browser session
- Customer accounts with a private **My orders** history
- Manager and administrator order lookup and refund workflows
- Manager inventory restocking
- Administrator user and role management
- Viewer read-only access to internal records
- CSRF protection on state-changing forms and cart operations

## Roles

- **Customer**: storefront, checkout, and their own order history
- **Viewer**: read-only internal workspace access
- **Manager**: orders, refunds, and inventory restocking
- **Administrator**: full management access, including users and roles

Guest orders are saved in the database even when the shopper is not signed in. The order number on the confirmation receipt can be used by a manager or administrator to find the transaction.

## Running locally

The project is intended for Code::Blocks with the MinGW GCC toolchain.

1. Open `SalesCartCheckout.cbp` in Code::Blocks.
2. Build the Debug target.
3. Run `bin/Debug/SalesCartCheckout.exe`.
4. Open [http://localhost:8080/store](http://localhost:8080/store).

The executable reads `SalesCartCheckout.ini` beside the executable. The configuration controls the host, port, database path, templates path, and static-file path. Paths are resolved from the executable's working directory.

The development database is intentionally local and ignored by Git. To initialize a new database, apply `data/seed.sql` with SQLite and update the `database` setting if needed.

## Main routes

- `/store` — public storefront
- `/cart` — current guest or customer cart
- `/checkout` — checkout review
- `/` — sign-in page
- `/my-orders` — signed-in customer order history
- `/dashboard` — internal workspace
- `/orders-view` — internal order list and order-number search

## Security notes

This is a local demonstration application, not a production payment system. Payment is simulated; the application does not accept or store card numbers. Keep local database files and private configuration out of source control, and use HTTPS plus secure cookies before deploying any real service.
