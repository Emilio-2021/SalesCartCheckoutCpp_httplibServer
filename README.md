# System Control Center

System Control Center is a C++17 business-management web application built with
[cpp-httplib](https://github.com/yhirose/cpp-httplib), SQLite, Inja templates,
and bcrypt password hashing.

It provides an internal dashboard for managing products, business entities,
users, inventory, sales orders, and refunds.

## Features

- Session-based login with SQLite-backed sessions.
- Secure random session identifiers stored in `HttpOnly` cookies.
- Per-session CSRF tokens for state-changing forms.
- Role-based access control for viewers, operators, and administrators.
- Product and entity management.
- Inventory-aware checkout and transactional order creation.
- Order details and transactional full refunds.
- Administrator-only user management with bcrypt password hashes.
- SQLite parameterized queries and server-side input validation.
- Dashboard and responsive Bootstrap-based pages.

## Technology

- C++17
- MinGW / GCC
- Code::Blocks project files
- SQLite
- cpp-httplib
- Inja
- nlohmann/json
- bcrypt
- Bootstrap

## Running locally

The application uses paths relative to its working directory. Run it from
`bin/Debug` so the bundled templates, static assets, and configuration file are
found correctly:

```text
cd bin/Debug
Testhttplib.exe
```

To use a different port:

```text
Testhttplib.exe 8081
```

Then open <http://127.0.0.1:8080> or the port selected at startup.

The local SQLite database is intentionally ignored by Git. Create a development
database from [`data/seed.sql`](data/seed.sql) before first use, using a SQLite
command-line tool or database browser.

## Building

Open [`Testhttplib.cbp`](Testhttplib.cbp) in Code::Blocks and build the Debug
target. The project is configured for the MinGW GCC compiler and links against
`ws2_32`.

SQLite must be compiled as C, while the application sources are compiled as
C++. The Code::Blocks project already declares the SQLite source with the C
compiler setting.

## Routes

| Area | Routes |
| --- | --- |
| Authentication | `/`, `/login`, `/logout` |
| Dashboard | `/dashboard` |
| Products | `/products-view`, `/products/create`, `/products/update`, `/products/delete/{id}` |
| Entities | `/entities-view`, `/entities/create`, `/entities/update`, `/entities/delete/{id}` |
| Orders | `/orders-view`, `/orders/{id}` |
| Checkout | `/checkout`, `/checkout/create` |
| Refunds | `/orders/{id}/refund` |
| Users | `/users-view`, `/users/create`, `/users/update`, `/users/delete/{id}` |

## Security notes

This is a development and portfolio project, not a production deployment.

- Passwords are never stored in plain text; bcrypt hashes are stored instead.
- Session cookies contain only an opaque session ID.
- CSRF tokens are required for state-changing requests.
- Viewer, operator, and administrator permissions are enforced server-side.
- Use HTTPS and enable the cookie `Secure` attribute before deployment.
- Do not commit real databases, credentials, API keys, or production configuration.
- Payment processing is not included; a future customer-facing project can use
  a provider such as Stripe Checkout in test mode.

For the current development behavior, all sessions are cleared when the server
starts, so restarting the server requires users to log in again.

## Project status

The internal management workflow is implemented. Future improvements include
broader automated integration tests, CSRF test coverage, and a separate
customer-facing shopping-cart and payment demonstration.

