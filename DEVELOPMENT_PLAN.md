# Development Plan

## Route development and authentication

1. [完成] Inventory the existing dashboard routes, templates, database tables, and current login behavior.
2. [完成] Design and implement server-side sessions with secure cookies, logout, and authentication checks.
3. [In progress] Add reusable authentication and authorization helpers, then protect dashboard and resource routes.
4. Implement missing resource routes incrementally, using the dashboard as the UI reference.
5. Validate each route with build checks and manual request-flow tests.

## Login/session direction

- Verify the submitted username and password on the server.
- Generate a random server-side session ID after successful authentication.
- Store the session ID, user ID, role, and expiration time on the server.
- Send only the session ID in an `HttpOnly` cookie.
- Use `SameSite=Lax` and `Secure` when HTTPS is enabled.
- Add logout by deleting the server-side session and expiring the cookie.
- Remove dashboard authentication through URL query parameters such as `username` and `role`.
