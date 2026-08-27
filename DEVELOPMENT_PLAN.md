# Development Plan

## Route development and authentication

1. [完成] Inventory the existing dashboard routes, templates, database tables, and current login behavior.
2. [完成] Design and implement server-side sessions with secure cookies, logout, and authentication checks.
3. [In progress] Add reusable authentication and authorization helpers, then protect dashboard and resource routes. Dashboard, product, entity, order, and checkout views require a valid session; product and entity write routes enforce the `admin` role.
4. [completed] Implement missing resource routes incrementally, using the dashboard as the UI reference. Product/entity management, order views, transactional checkout, full refunds, and user management are implemented.
5. [In progress] Validate each route with build checks and manual request-flow tests. Unauthenticated route protection, invalid login/port handling, CSRF implementation, and session initialization have been smoke-tested; authenticated end-to-end coverage remains.

## Security hardening follow-up

- [completed] Add CSRF tokens to all state-changing forms and validate them server-side.
- Use the `Secure` cookie attribute when HTTPS is enabled.
- Add broader authenticated tests for viewer, operator, and administrator permissions.
- SQLite session lookups now avoid nested writes while a result is open and use a short busy timeout for concurrent access.

## Login/session direction

- Verify the submitted username and password on the server.
- Generate a random server-side session ID after successful authentication.
- Store the session ID, user ID, role, and expiration time on the server.
- Send only the session ID in an `HttpOnly` cookie.
- Use `SameSite=Lax` and `Secure` when HTTPS is enabled.
- Add logout by deleting the server-side session and expiring the cookie.
- Clear all sessions when the single-server application starts, so a server restart requires login again.
- Remove dashboard authentication through URL query parameters such as `username` and `role`.
