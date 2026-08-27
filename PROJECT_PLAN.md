# Sales Cart Checkout Demo — Project Plan

## Project goal

Create a customer-facing shopping-cart and checkout demonstration based on the
existing System Control Center C++ application. The project should demonstrate
product browsing, a session-based cart, checkout validation, simulated payment,
order creation, inventory updates, and a polished customer experience.

This is a portfolio and development project. It must not store real payment-card
data or process real payments. If payment-provider integration is added, use a
provider's test mode and hosted checkout flow.

## Starting point

The project was copied from the internal management application, but the
original `.git` directory and Markdown documentation were intentionally omitted.
The new project must receive its own Git repository and documentation.

Existing technologies to preserve where useful:

- C++17 and MinGW/GCC.
- Code::Blocks project configuration.
- cpp-httplib HTTP server.
- SQLite and the existing `Liteqry` wrapper.
- Inja templates and nlohmann/json.
- bcrypt for password hashing where customer/admin authentication is needed.
- Bootstrap for responsive UI.

## Product direction

The application should present a customer-facing storefront while keeping
administrative operations separate from the original project.

Core customer flow:

```text
Browse products → Add to cart → Review cart → Checkout → Payment test →
Create order → Show confirmation
```

## Application roles

The application uses separate customer and internal-management permissions:

- `admin`: full system control, including users, roles, managers, and settings.
- `manager`: day-to-day product restocking, operational orders, and refunds.
- `viewer`: read-only access to internal management pages.
- `customer`: storefront, cart, checkout, and the customer's own orders only.

The existing `operator` role will be renamed to `manager`. Existing database
users with the `operator` role must be migrated to `manager`. Customers must
not receive access to internal dashboards or administrative data.

Guest browsing and checkout are allowed. A customer account is required for
account-based order history and other personalized features.

## Implementation phases

### Phase 1 — Inspect and rename

- Inspect the copied files and confirm the project builds from the new folder.
- Rename the application/project title to `SalesCartCheckout` where appropriate.
- Confirm runtime paths work from `bin/Debug`.
- Keep the existing database schema unless a change is necessary.
- Add a new `.gitignore` suitable for this repository.
- Add this plan and a project-specific `README.md`.

### Phase 2 — Customer product browsing

- Add a storefront route such as `GET /store` or `GET /products`.
- Display product name, SKU, price, and available stock.
- Do not expose administrative edit/delete controls.
- Validate all product data on the server.
- Use parameterized SQLite queries.
- Add product detail pages only if they improve the demonstration.

### Phase 3 — Session-based shopping cart

- Use the existing session mechanism as the foundation.
- Add a cart associated with the authenticated customer or guest session.
- Support adding a product and quantity.
- Support changing quantity and removing items.
- Display subtotal and item count.
- Recheck product existence, price, and stock on every cart-changing request.
- Never trust prices or totals submitted by the browser.
- Protect all cart mutations with CSRF tokens.

### Phase 4 — Checkout review

- Add a checkout page showing customer/order information and cart contents.
- Recalculate totals on the server.
- Validate quantities, available inventory, and required customer fields.
- Prevent duplicate submissions where practical.
- Display clear validation errors without exposing database details.

### Phase 5 — Payment demonstration

Preferred first implementation:

- Add a clearly labeled simulated payment step.
- Provide success and failure outcomes for demonstration.
- Only create the order after simulated payment succeeds.
- Store a payment status such as `SIMULATED_PAID`, not sensitive payment data.

Optional later implementation:

- Integrate a hosted Stripe Checkout test-mode flow.
- Store only the provider checkout/session identifier and payment status.
- Verify payment completion server-side or through a signed webhook.
- Never accept or store card numbers, CVV values, or raw payment details.

### Phase 6 — Transactional order creation

- Create the order and line items in one SQLite transaction.
- Snapshot the server-confirmed product prices into `order_items`.
- Decrement inventory only when the transaction succeeds.
- Use conditional stock updates to prevent overselling.
- Roll back the full transaction on any failure.
- Redirect to an order-confirmation page after success.

### Phase 7 — Customer order history

- Add an authenticated `GET /my-orders` route.
- Show only orders belonging to the current customer account.
- Add an order-detail page.
- Do not allow customers to alter inventory or order totals.
- Keep refund administration restricted to admins and managers unless a
  customer refund request flow is intentionally added later.

### Phase 8 — Testing and portfolio polish

- Test unauthenticated access and redirect behavior.
- Test cart add/update/remove behavior.
- Test invalid product IDs, invalid quantities, zero stock, and stale prices.
- Test CSRF rejection for cart and checkout mutations.
- Test transaction rollback by forcing an order-write failure.
- Test duplicate checkout submission behavior.
- Test payment success and failure paths.
- Test that one customer cannot view another customer's orders.
- Rebuild with warnings enabled.
- Add screenshots or a short demo GIF to the README.
- Document architecture and security decisions.

## Suggested routes

| Purpose | Route | Method |
| --- | --- | --- |
| Storefront | `/store` | GET |
| Product details | `/store/product/{id}` | GET |
| Add item | `/cart/add` | POST |
| View cart | `/cart` | GET |
| Update cart | `/cart/update` | POST |
| Remove item | `/cart/remove` | POST |
| Checkout review | `/checkout` | GET |
| Submit checkout/payment test | `/checkout/submit` | POST |
| Confirmation | `/orders/confirmation/{id}` | GET |
| Customer orders | `/my-orders` | GET |
| Customer order detail | `/my-orders/{id}` | GET |

Route names may change after inspecting the copied application. Keep the final
route list synchronized with the README.

## Data model considerations

The existing `products`, `orders`, and `order_items` tables can support the
first version. Consider adding these only when needed:

- `cart_items` if carts must survive server restarts or work across devices.
- `payments` for simulated/provider payment status and identifiers.
- A customer/account relation if customer authentication is separated from
  internal users.

Customer accounts should be separated from internal admin, manager, and
viewer access. Guest carts may remain session-based for the first milestone.

For the first milestone, an in-session cart is acceptable. Persistent carts can
be a later enhancement.

## Security requirements

- Keep session cookies `HttpOnly` and `SameSite=Lax`.
- Use `Secure` when running over HTTPS.
- Require CSRF tokens on every state-changing form.
- Validate every ID, quantity, email, and payment status on the server.
- Enforce role boundaries: customers cannot access internal management routes,
  and managers cannot administer users or roles.
- Use parameterized SQL for all user-controlled values.
- Recalculate all prices and totals server-side.
- Do not trust browser stock, price, role, or payment fields.
- Do not store payment-card information.
- Avoid logging passwords, session IDs, CSRF tokens, or payment identifiers.
- Keep local databases and credentials out of Git.

## Milestones

1. New project builds and displays the storefront.
2. Cart can add, update, remove, and calculate totals.
3. Checkout validates the cart and shows a payment-test step.
4. Successful payment creates an order and decrements inventory atomically.
5. Customer can view the confirmation and their order history.
6. Tests, README, screenshots, and GitHub repository are complete.

## GitHub handoff

- Initialize a new Git repository in this folder.
- Use a new repository name such as `sales-cart-checkout-demo`.
- Do not copy the original project's `.git` history.
- Add the new project-specific README before the first public push.
- Confirm no database files, credentials, build outputs, or private configuration
  files are tracked.
