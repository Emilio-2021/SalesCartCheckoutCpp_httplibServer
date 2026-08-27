//--------------------------------------------------------------------------------------------------
#define _WIN32_WINNT 0x0A00
#include <iostream>
//using namespace std;
using std::string;
//--------------------------------------------------------------------------------------------------
//#define CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_NO_OPENSSL
//--------------------------------------------------------------------------------------------------
#include "httplib.h"
#include "inja/inja.hpp"
#include "nlohmann/json.hpp"
#include "sqlite/sqlite3.h"
#include "bcrypt/scc_bcrypt.h"
#include "Liteqry.h"
#include "session_store.h"
#include "cart_store.h"
#include <fstream>
#include <filesystem>
#include <functional>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <sstream>
#include <vector>
// HTTPS
//httplib::SSLServer svr;

//--------------------------------------------------------------------------------------------------
void print(const string& msg) {
    std::cout << msg << std::endl;
}
//--------------------------------------------------------------------------------------------------
// A template function that accepts almost anything
template <typename T>
void printAll(const T& msg) {
    std::cout << msg << std::endl;
}
//--------------------------------------------------------------------------------------------------
struct AppConfig {
    string host = "127.0.0.1";
    int port = 8080;
    string databasePath = "data/salescart.db";
    string templatesPath = "templates/";
    string staticPath = "static/";
};
//--------------------------------------------------------------------------------------------------
struct CartContext {
    string id;
    CartSnapshot snapshot;
};

std::optional<string> getCookie(const httplib::Request& req, const string& name);

CartContext getCartContext(const httplib::Request& req,
                           httplib::Response& res,
                           CartStore& carts) {
    const auto existingId = getCookie(req, "scc_cart");
    const string cartId = existingId && !existingId->empty() ? *existingId : createSessionId();
    if (!existingId || existingId->empty()) {
        res.set_header("Set-Cookie",
                       "scc_cart=" + cartId + "; Path=/; HttpOnly; SameSite=Lax");
    }
    return CartContext{cartId, carts.getOrCreate(cartId)};
}

bool requireCartCsrf(const httplib::Request& req,
                     httplib::Response& res,
                     CartStore& carts,
                     const string& cartId) {
    if (carts.hasValidCsrf(cartId, req.get_param_value("csrf_token"))) return true;

    res.status = 403;
    res.set_content("Invalid CSRF token", "text/plain; charset=UTF-8");
    return false;
}
//--------------------------------------------------------------------------------------------------
static string trim(const string& value) {
    const string whitespace = " \t\r\n";
    const std::size_t first = value.find_first_not_of(whitespace);
    if (first == string::npos) return "";
    const std::size_t last = value.find_last_not_of(whitespace);
    return value.substr(first, last - first + 1);
}
//--------------------------------------------------------------------------------------------------
std::optional<string> getCookie(const httplib::Request& req, const string& name) {
    const string cookieHeader = req.get_header_value("Cookie");
    std::size_t start = 0;

    while (start < cookieHeader.size()) {
        const std::size_t end = cookieHeader.find(';', start);
        const string item = trim(cookieHeader.substr(start, end - start));
        const std::size_t separator = item.find('=');

        if (separator != string::npos && trim(item.substr(0, separator)) == name) {
            return trim(item.substr(separator + 1));
        }

        if (end == string::npos) break;
        start = end + 1;
    }

    return std::nullopt;
}
//--------------------------------------------------------------------------------------------------
std::optional<UserSession> getSession(const httplib::Request& req,
                                      SessionStore& sessions,
                                      std::mutex&) {
    const auto sessionId = getCookie(req, "scc_session");
    if (!sessionId || sessionId->empty()) return std::nullopt;
    return sessions.find(*sessionId);
}
//--------------------------------------------------------------------------------------------------
void clearSessionCookie(httplib::Response& res) {
    res.set_header("Set-Cookie",
                   "scc_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
}
//--------------------------------------------------------------------------------------------------
bool requireSession(const httplib::Request& req,
                    httplib::Response& res,
                    SessionStore& sessions,
                    std::mutex& sessionsMutex,
                    UserSession& session) {
    const auto authenticatedSession = getSession(req, sessions, sessionsMutex);
    if (!authenticatedSession) {
        res.set_redirect("/", 302);
        return false;
    }

    session = *authenticatedSession;
    return true;
}
//--------------------------------------------------------------------------------------------------
bool requireCsrfToken(const httplib::Request& req,
                      httplib::Response& res,
                      const UserSession& session) {
    if (req.get_param_value("csrf_token") == session.csrfToken && !session.csrfToken.empty()) {
        return true;
    }

    res.status = 403;
    res.set_content("Invalid CSRF token", "text/plain; charset=UTF-8");
    return false;
}
//--------------------------------------------------------------------------------------------------
bool requireRole(const UserSession& session,
                 httplib::Response& res,
                 const std::vector<string>& allowedRoles) {
    for (const auto& allowedRole : allowedRoles) {
        if (session.role == allowedRole) return true;
    }

    res.status = 403;
    res.set_content("Forbidden", "text/plain; charset=UTF-8");
    return false;
}
//--------------------------------------------------------------------------------------------------
bool requireAdmin(const httplib::Request& req,
                  httplib::Response& res,
                  SessionStore& sessions,
                  std::mutex& sessionsMutex,
                  UserSession& session) {
    if (!requireSession(req, res, sessions, sessionsMutex, session) ||
        !requireRole(session, res, {"admin"})) return false;
    return req.method != "POST" || requireCsrfToken(req, res, session);
}

bool requireManager(const httplib::Request& req,
                    httplib::Response& res,
                    SessionStore& sessions,
                    std::mutex& sessionsMutex,
                    UserSession& session) {
    if (!requireSession(req, res, sessions, sessionsMutex, session) ||
        !requireRole(session, res, {"admin", "manager"})) return false;
    return req.method != "POST" || requireCsrfToken(req, res, session);
}
//--------------------------------------------------------------------------------------------------
bool parseInteger(const string& text, int& value, int minimum) {
    try {
        std::size_t consumed = 0;
        const long long parsed = std::stoll(text, &consumed);
        if (consumed != text.size() || parsed < minimum || parsed > 2147483647LL) {
            return false;
        }
        value = static_cast<int>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}
//--------------------------------------------------------------------------------------------------
bool parseMoney(const string& text, string& value) {
    try {
        std::size_t consumed = 0;
        const double parsed = std::stod(text, &consumed);
        if (consumed != text.size() || !std::isfinite(parsed) || parsed < 0) return false;

        std::ostringstream normalized;
        normalized << std::fixed << std::setprecision(2) << parsed;
        value = normalized.str();
        return true;
    } catch (...) {
        return false;
    }
}
//--------------------------------------------------------------------------------------------------
bool parseEntityType(const string& text, int& entityType) {
    if (text == "1" || text == "Customer" || text == "PERSON") {
        entityType = 1;
        return true;
    }
    if (text == "2" || text == "Supplier" || text == "COMPANY") {
        entityType = 2;
        return true;
    }
    return false;
}
//--------------------------------------------------------------------------------------------------
bool isValidRole(const string& role) {
    return role == "viewer" || role == "manager" || role == "customer" || role == "admin";
}
//--------------------------------------------------------------------------------------------------
string configPathFromExecutable(const char* executablePath) {
    if (executablePath == nullptr || string(executablePath).empty()) {
        return "app.ini";
    }

    const std::filesystem::path executable(executablePath);
    return (executable.parent_path() / (executable.stem().string() + ".ini")).string();
}

AppConfig iniConfig(const string& iniPath) {
    AppConfig config;
    std::ifstream file(iniPath);

    if (!file.is_open()) {
        print("Configuration file not found: " + iniPath + ". Using defaults.");
        return config;
    }

    string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;

        const std::size_t separator = line.find('=');
        if (separator == string::npos) continue;

        const string key = trim(line.substr(0, separator));
        const string value = trim(line.substr(separator + 1));

        if (key == "host") config.host = value;
        else if (key == "port") config.port = std::stoi(value);
        else if (key == "database") config.databasePath = value;
        else if (key == "templates") config.templatesPath = value;
        else if (key == "static") config.staticPath = value;
    }

    return config;
}
//--------------------------------------------------------------------------------------------------
// Helper function to read an HTML file from disk
string loadHTMLFile(const string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return "<h1>404 Not Found</h1><p>Could not find the HTML file.</p>";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}
//--------------------------------------------------------------------------------------------------
// A helper function to wrap any route handler with automatic try-catch error handling
void safeRoute(httplib::Server& svr, const string& path, std::function<void(const httplib::Request&, httplib::Response&)> handler, bool isPost = false) {
    auto wrappedHandler = [handler](const httplib::Request& req, httplib::Response& res) {
        try {
            handler(req, res);
        } catch (const std::exception& e) {
//            std::cout << "ROUTE CRASH EXCEPTION (" << req.path << "): " << e.what() << "\n";
            print("ROUTE CRASH EXCEPTION (" + req.path + "): " + e.what() );
            res.status = 500;
            res.set_content("Internal Server Error: " + string(e.what()), "text/plain");
        } catch (...) {
//            std::cout << "UNKNOWN ROUTE CRASH (" << req.path << ")\n";
            print("UNKNOWN ROUTE CRASH (" + req.path + ")");
            res.status = 500;
            res.set_content("Internal Server Error: Unknown Exception", "text/plain");
        }
    };

    if (isPost) {
        svr.Post(path, wrappedHandler);
    } else {
        svr.Get(path, wrappedHandler);
    }
}
//--------------------------------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    AppConfig config = iniConfig(configPathFromExecutable(argc > 0 ? argv[0] : nullptr));

	if (argc > 2) {
		std::cerr << "Usage: SalesCartCheckout [port]\n";
		return 1;
	}

	if (argc > 1) {
        const auto requested_port = std::strtol(argv[1], nullptr, 10);
        if (requested_port < 1 || requested_port > 65535) {
			std::cerr << "Invalid port: " << argv[1] << "\n";
            return 1;
        }
        config.port = requested_port;
    }

    httplib::Server svr;
    SessionStore sessions(config.databasePath);
    sessions.initialize();
    CartStore carts;
    std::mutex sessionsMutex;

    {
        Liteqry db(config.databasePath);
        db.execute(
            "CREATE TABLE IF NOT EXISTS payments ("
            "id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL, "
            "status VARCHAR(30) NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);");
    }

    if (!svr.set_mount_point("/static", config.staticPath)) {
        throw std::runtime_error("Could not mount static directory");
    }
    inja::Environment env(config.templatesPath);
    // 1. Public storefront entry point
    safeRoute(svr, "/", [&](const httplib::Request&, httplib::Response& res) {
        res.set_redirect("/store", 302);
    });

    // 2. Login page (GET)
    safeRoute(svr, "/login", [&](const httplib::Request&, httplib::Response& res) {
        nlohmann::json data;
        data["error"] = "";
        string html = env.render_file("login.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 3. Customer storefront (GET; public)
    safeRoute(svr, "/store", [&](const httplib::Request& req, httplib::Response& res) {
        const CartContext cart = getCartContext(req, res, carts);
        Liteqry db(config.databasePath);
        auto rows = db.query(
            "SELECT id, name, sku, printf('%.2f', price) AS price, stock_quantity "
            "FROM products ORDER BY name ASC, id ASC;");

        nlohmann::json data;
        data["products"] = nlohmann::json::array();
        int cartItemCount = 0;
        double cartSubtotal = 0.0;
        while (rows.next()) {
            nlohmann::json product;
            product["id"] = rows.at("id");
            product["name"] = rows.at("name");
            product["sku"] = rows.at("sku");
            product["price"] = rows.at("price");
            product["stock_quantity"] = rows.at("stock_quantity");
            product["in_stock"] = rows.at("stock_quantity") != "0";
            const auto cartItem = cart.snapshot.quantities.find(std::stoi(rows.at("id")));
            const int cartQuantity = cartItem == cart.snapshot.quantities.end() ? 0 : cartItem->second;
            product["cart_quantity"] = cartQuantity;
            cartItemCount += cartQuantity;
            cartSubtotal += std::stod(rows.at("price")) * cartQuantity;
            data["products"].push_back(product);
        }
        data["product_count"] = data["products"].size();
        data["csrf_token"] = cart.snapshot.csrfToken;
        const auto signedInSession = getSession(req, sessions, sessionsMutex);
        data["is_customer"] = signedInSession && signedInSession->role == "customer";
        data["cart_item_count"] = cartItemCount;
        std::ostringstream formattedCartSubtotal;
        formattedCartSubtotal << std::fixed << std::setprecision(2) << cartSubtotal;
        data["cart_subtotal"] = formattedCartSubtotal.str();

        string html = env.render_file("store.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 3. View the customer cart (GET; public)
    safeRoute(svr, "/cart", [&](const httplib::Request& req, httplib::Response& res) {
        const CartContext cart = getCartContext(req, res, carts);
        Liteqry db(config.databasePath);
        nlohmann::json data;
        data["items"] = nlohmann::json::array();
        data["item_count"] = 0;
        data["subtotal"] = "0.00";
        data["csrf_token"] = cart.snapshot.csrfToken;

        long long itemCount = 0;
        double subtotal = 0.0;
        for (const auto& entry : cart.snapshot.quantities) {
            auto product = db.query(
                "SELECT id, name, sku, printf('%.2f', price) AS price, stock_quantity "
                "FROM products WHERE id = ?;", {std::to_string(entry.first)});
            if (!product.next()) continue;

            const int quantity = entry.second;
            const double price = std::stod(product.at("price"));
            nlohmann::json item;
            item["id"] = product.at("id");
            item["name"] = product.at("name");
            item["sku"] = product.at("sku");
            item["price"] = product.at("price");
            item["quantity"] = quantity;
            item["stock_quantity"] = product.at("stock_quantity");
            item["line_total"] = [&]() {
                std::ostringstream total;
                total << std::fixed << std::setprecision(2) << price * quantity;
                return total.str();
            }();
            data["items"].push_back(item);
            itemCount += quantity;
            subtotal += price * quantity;
        }

        std::ostringstream formattedSubtotal;
        formattedSubtotal << std::fixed << std::setprecision(2) << subtotal;
        data["item_count"] = itemCount;
        data["subtotal"] = formattedSubtotal.str();

        string html = env.render_file("cart.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 4. Add a product to the customer cart (POST; public with CSRF)
    safeRoute(svr, "/cart/add", [&](const httplib::Request& req, httplib::Response& res) {
        const CartContext cart = getCartContext(req, res, carts);
        if (!requireCartCsrf(req, res, carts, cart.id)) return;

        int productId = 0;
        int quantity = 0;
        if (!parseInteger(req.get_param_value("product_id"), productId, 1) ||
            !parseInteger(req.get_param_value("quantity"), quantity, 1)) {
            res.status = 400;
            res.set_content("Invalid cart item", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        auto product = db.query(
            "SELECT stock_quantity FROM products WHERE id = ?;",
            {std::to_string(productId)});
        if (!product.next()) {
            res.status = 404;
            res.set_content("Product not found", "text/plain; charset=UTF-8");
            return;
        }

        int stock = 0;
        if (!parseInteger(product.at("stock_quantity"), stock, 0)) {
            res.status = 500;
            res.set_content("Invalid product stock", "text/plain; charset=UTF-8");
            return;
        }
        const auto existing = cart.snapshot.quantities.find(productId);
        const long long requested = (existing == cart.snapshot.quantities.end() ? 0 : existing->second) + quantity;
        if (requested > stock) {
            res.status = 409;
            res.set_content("Requested quantity exceeds available stock", "text/plain; charset=UTF-8");
            return;
        }

        carts.setQuantity(cart.id, productId, static_cast<int>(requested));
        res.set_redirect("/store", 303);
    }, true);

    // 5. Update a customer cart item (POST; public with CSRF)
    safeRoute(svr, "/cart/update", [&](const httplib::Request& req, httplib::Response& res) {
        const CartContext cart = getCartContext(req, res, carts);
        if (!requireCartCsrf(req, res, carts, cart.id)) return;

        int productId = 0;
        int quantity = 0;
        if (!parseInteger(req.get_param_value("product_id"), productId, 1) ||
            !parseInteger(req.get_param_value("quantity"), quantity, 1)) {
            res.status = 400;
            res.set_content("Invalid cart item", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        auto product = db.query(
            "SELECT stock_quantity FROM products WHERE id = ?;",
            {std::to_string(productId)});
        int stock = 0;
        if (!product.next() || !parseInteger(product.at("stock_quantity"), stock, 0)) {
            res.status = 404;
            res.set_content("Product not found", "text/plain; charset=UTF-8");
            return;
        }
        if (quantity > stock) {
            res.status = 409;
            res.set_content("Requested quantity exceeds available stock", "text/plain; charset=UTF-8");
            return;
        }

        carts.setQuantity(cart.id, productId, quantity);
        res.set_redirect("/cart", 303);
    }, true);

    // 6. Remove a customer cart item (POST; public with CSRF)
    safeRoute(svr, "/cart/remove", [&](const httplib::Request& req, httplib::Response& res) {
        const CartContext cart = getCartContext(req, res, carts);
        if (!requireCartCsrf(req, res, carts, cart.id)) return;

        int productId = 0;
        if (!parseInteger(req.get_param_value("product_id"), productId, 1)) {
            res.status = 400;
            res.set_content("Invalid product ID", "text/plain; charset=UTF-8");
            return;
        }

        carts.remove(cart.id, productId);
        res.set_redirect("/cart", 303);
    }, true);

    // 7. Customer checkout review (GET; public)
    safeRoute(svr, "/checkout", [&](const httplib::Request& req, httplib::Response& res) {
        const CartContext cart = getCartContext(req, res, carts);
        if (cart.snapshot.quantities.empty()) {
            res.set_redirect("/cart", 303);
            return;
        }

        Liteqry db(config.databasePath);
        nlohmann::json data;
        data["items"] = nlohmann::json::array();
        data["csrf_token"] = cart.snapshot.csrfToken;
        double subtotal = 0.0;
        int itemCount = 0;
        bool canCheckout = true;
        for (const auto& entry : cart.snapshot.quantities) {
            auto product = db.query(
                "SELECT id, name, sku, printf('%.2f', price) AS price, stock_quantity "
                "FROM products WHERE id = ?;", {std::to_string(entry.first)});
            if (!product.next()) {
                canCheckout = false;
                continue;
            }

            const int quantity = entry.second;
            int stock = 0;
            parseInteger(product.at("stock_quantity"), stock, 0);
            const double price = std::stod(product.at("price"));
            nlohmann::json item;
            item["name"] = product.at("name");
            item["sku"] = product.at("sku");
            item["price"] = product.at("price");
            item["quantity"] = quantity;
            item["line_total"] = [&]() {
                std::ostringstream total;
                total << std::fixed << std::setprecision(2) << price * quantity;
                return total.str();
            }();
            item["stock_ok"] = quantity <= stock;
            if (quantity > stock) canCheckout = false;
            data["items"].push_back(item);
            subtotal += price * quantity;
            itemCount += quantity;
        }

        std::ostringstream formattedSubtotal;
        formattedSubtotal << std::fixed << std::setprecision(2) << subtotal;
        data["subtotal"] = formattedSubtotal.str();
        data["item_count"] = itemCount;
        data["can_checkout"] = canCheckout && !data["items"].empty();

        string html = env.render_file("checkout_review.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 8. Validate checkout details and show simulated payment (POST; public with CSRF)
    safeRoute(svr, "/checkout/submit", [&](const httplib::Request& req, httplib::Response& res) {
        const CartContext cart = getCartContext(req, res, carts);
        if (!requireCartCsrf(req, res, carts, cart.id)) return;

        const string customerName = trim(req.get_param_value("customer_name"));
        const string customerEmail = trim(req.get_param_value("customer_email"));
        const string shippingAddress = trim(req.get_param_value("shipping_address"));
        const std::size_t at = customerEmail.find('@');
        const bool validEmail = at != string::npos && at > 0 &&
                                customerEmail.find('.', at + 1) != string::npos;
        if (customerName.empty() || customerName.size() > 150 ||
            !validEmail || customerEmail.size() > 150 ||
            shippingAddress.empty() || shippingAddress.size() > 300) {
            res.status = 400;
            res.set_content("Please provide valid customer information", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        nlohmann::json data;
        data["customer_name"] = customerName;
        data["customer_email"] = customerEmail;
        data["shipping_address"] = shippingAddress;
        data["csrf_token"] = cart.snapshot.csrfToken;
        data["items"] = nlohmann::json::array();
        double subtotal = 0.0;
        for (const auto& entry : cart.snapshot.quantities) {
            auto product = db.query(
                "SELECT name, printf('%.2f', price) AS price, stock_quantity "
                "FROM products WHERE id = ?;", {std::to_string(entry.first)});
            int stock = 0;
            if (!product.next() || !parseInteger(product.at("stock_quantity"), stock, 0) ||
                entry.second > stock) {
                res.status = 409;
                res.set_content("Cart stock has changed. Please review your cart.", "text/plain; charset=UTF-8");
                return;
            }

            const double price = std::stod(product.at("price"));
            nlohmann::json item;
            item["name"] = product.at("name");
            item["price"] = product.at("price");
            item["quantity"] = entry.second;
            data["items"].push_back(item);
            subtotal += price * entry.second;
        }

        std::ostringstream formattedSubtotal;
        formattedSubtotal << std::fixed << std::setprecision(2) << subtotal;
        data["subtotal"] = formattedSubtotal.str();
        string html = env.render_file("payment.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    }, true);

    // 9. Simulate payment success or failure (POST; public with CSRF)
    safeRoute(svr, "/checkout/payment", [&](const httplib::Request& req, httplib::Response& res) {
        const CartContext cart = getCartContext(req, res, carts);
        if (!requireCartCsrf(req, res, carts, cart.id)) return;

        const string customerName = trim(req.get_param_value("customer_name"));
        const string customerEmail = trim(req.get_param_value("customer_email"));
        const string shippingAddress = trim(req.get_param_value("shipping_address"));
        const std::size_t at = customerEmail.find('@');
        const bool validEmail = at != string::npos && at > 0 &&
                                customerEmail.find('.', at + 1) != string::npos;
        if (customerName.empty() || customerName.size() > 150 ||
            !validEmail || customerEmail.size() > 150 ||
            shippingAddress.empty() || shippingAddress.size() > 300) {
            res.status = 400;
            res.set_content("Please provide valid customer information", "text/plain; charset=UTF-8");
            return;
        }

        const string paymentOutcome = req.get_param_value("payment_outcome");
        if (paymentOutcome != "success" && paymentOutcome != "failure") {
            res.status = 400;
            res.set_content("Invalid simulated payment outcome", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        for (const auto& entry : cart.snapshot.quantities) {
            auto product = db.query(
                "SELECT stock_quantity FROM products WHERE id = ?;",
                {std::to_string(entry.first)});
            int stock = 0;
            if (!product.next() || !parseInteger(product.at("stock_quantity"), stock, 0) ||
                entry.second > stock) {
                res.status = 409;
                res.set_content("Cart stock has changed. Please review your cart.", "text/plain; charset=UTF-8");
                return;
            }
        }

        nlohmann::json data;
        data["success"] = paymentOutcome == "success";
        data["payment_status"] = data["success"] ? "SIMULATED_PAID" : "SIMULATED_FAILED";
        data["csrf_token"] = cart.snapshot.csrfToken;

        if (paymentOutcome == "success") {
            string orderId;
            try {
                db.execute("BEGIN IMMEDIATE TRANSACTION;");
                db.execute(
                    "INSERT INTO entities (entity_type, name, email) VALUES (1, ?, ?);",
                    {customerName, customerEmail});

                string entityId;
                {
                    auto entity = db.query("SELECT last_insert_rowid() AS id;");
                    if (!entity.next()) throw std::runtime_error("Could not create customer");
                    entityId = entity.at("id");
                }

                const auto authenticatedCustomer = getSession(req, sessions, sessionsMutex);
                const string customerUserId = authenticatedCustomer &&
                    authenticatedCustomer->role == "customer" ? authenticatedCustomer->userId : "";
                db.execute(
                    "INSERT INTO orders (entity_id, user_id, status) VALUES (?, NULLIF(?, ''), 'COMPLETED');",
                    {entityId, customerUserId});
                {
                    auto order = db.query("SELECT last_insert_rowid() AS id;");
                    if (!order.next()) throw std::runtime_error("Could not create order");
                    orderId = order.at("id");
                }

                for (const auto& entry : cart.snapshot.quantities) {
                    string unitPrice;
                    {
                        auto product = db.query(
                            "SELECT printf('%.2f', price) AS price FROM products WHERE id = ?;",
                            {std::to_string(entry.first)});
                        if (!product.next()) throw std::runtime_error("Product no longer exists");
                        unitPrice = product.at("price");
                    }

                    if (db.execute(
                            "UPDATE products SET stock_quantity = stock_quantity - ? "
                            "WHERE id = ? AND stock_quantity >= ?;",
                            {std::to_string(entry.second), std::to_string(entry.first),
                             std::to_string(entry.second)}) != 1) {
                        throw std::runtime_error("Product stock changed during checkout");
                    }
                    db.execute(
                        "INSERT INTO order_items (order_id, product_id, quantity, unit_price) "
                        "VALUES (?, ?, ?, ?);",
                        {orderId, std::to_string(entry.first), std::to_string(entry.second), unitPrice});
                }

                db.execute(
                    "INSERT INTO payments (order_id, status) VALUES (?, 'SIMULATED_PAID');",
                    {orderId});
                db.execute("COMMIT;");
            } catch (...) {
                try { db.execute("ROLLBACK;"); } catch (...) {}
                res.status = 409;
                res.set_content("Could not complete the order. Please review your cart and try again.",
                                "text/plain; charset=UTF-8");
                return;
            }

            carts.clear(cart.id);
            carts.setLastOrderId(cart.id, orderId);
            data["order_id"] = orderId;
        }

        string html = env.render_file("payment_result.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    }, true);

    // 10. Customer order confirmation (GET; public for the completing cart session)
    safeRoute(svr, "/orders/confirmation/(\\d+)", [&](const httplib::Request& req, httplib::Response& res) {
        const CartContext cart = getCartContext(req, res, carts);
        const string orderId = req.matches[1].str();
        if (cart.snapshot.lastOrderId != orderId) {
            res.status = 404;
            res.set_content("Order confirmation not found", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        auto order = db.query(
            "SELECT o.id, e.name, e.email, o.status, o.created_at, "
            "COALESCE(pay.status, 'UNKNOWN') AS payment_status, "
            "printf('%.2f', COALESCE(SUM(oi.quantity * oi.unit_price), 0)) AS order_total "
            "FROM orders o JOIN entities e ON e.id = o.entity_id "
            "LEFT JOIN payments pay ON pay.order_id = o.id "
            "LEFT JOIN order_items oi ON oi.order_id = o.id "
            "WHERE o.id = ? GROUP BY o.id;", {orderId});
        if (!order.next()) {
            res.status = 404;
            res.set_content("Order confirmation not found", "text/plain; charset=UTF-8");
            return;
        }

        nlohmann::json data;
        data["order_id"] = order.at("id");
        data["customer_name"] = order.at("name");
        data["customer_email"] = order.at("email");
        data["status"] = order.at("status");
        data["payment_status"] = order.at("payment_status");
        data["created_at"] = order.at("created_at");
        data["order_total"] = order.at("order_total");
        data["items"] = nlohmann::json::array();

        auto items = db.query(
            "SELECT p.name, p.sku, oi.quantity, printf('%.2f', oi.unit_price) AS unit_price, "
            "printf('%.2f', oi.quantity * oi.unit_price) AS line_total "
            "FROM order_items oi JOIN products p ON p.id = oi.product_id "
            "WHERE oi.order_id = ? ORDER BY oi.id ASC;", {orderId});
        while (items.next()) {
            nlohmann::json item;
            item["name"] = items.at("name");
            item["sku"] = items.at("sku");
            item["quantity"] = items.at("quantity");
            item["unit_price"] = items.at("unit_price");
            item["line_total"] = items.at("line_total");
            data["items"].push_back(item);
        }

        string html = env.render_file("order_confirmation.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 11. Customer order history (GET; customers can view only their own orders)
    safeRoute(svr, "/my-orders", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireSession(req, res, sessions, sessionsMutex, session)) return;
        if (!requireRole(session, res, {"customer"})) return;

        Liteqry db(config.databasePath);
        auto orderRows = db.query(
            "SELECT o.id AS order_id, o.status, o.created_at, "
            "COALESCE(pay.status, 'UNKNOWN') AS payment_status, "
            "printf('%.2f', COALESCE(SUM(oi.quantity * oi.unit_price), 0)) AS order_total "
            "FROM orders o "
            "LEFT JOIN payments pay ON pay.order_id = o.id "
            "LEFT JOIN order_items oi ON oi.order_id = o.id "
            "WHERE o.user_id = ? GROUP BY o.id "
            "ORDER BY o.created_at DESC, o.id DESC;",
            {session.userId});

        nlohmann::json data;
        data["username"] = session.username;
        data["role"] = session.role;
        data["orders"] = nlohmann::json::array();
        while (orderRows.next()) {
            nlohmann::json order;
            order["order_id"] = orderRows.at("order_id");
            order["status"] = orderRows.at("status");
            order["payment_status"] = orderRows.at("payment_status");
            order["created_at"] = orderRows.at("created_at");
            order["order_total"] = orderRows.at("order_total");
            data["orders"].push_back(order);
        }

        string html = env.render_file("my_orders.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 12. Login handler (POST) - Notice the 'true' at the end for POST requests!
    safeRoute(svr, "/login", [&](const httplib::Request& req, httplib::Response& res) {
        string username = req.get_param_value("username");
        string password = req.get_param_value("password");

        string userId;
        string storedHash;
        {
            Liteqry db(config.databasePath);
            auto result = db.query(
                "SELECT id, password_hash FROM users WHERE username = ?;",
                {username});
            if (result.next()) {
                userId = result.at("id");
                storedHash = result.at("password_hash");
            }
        }

        bool loginSuccess = false;
        if (!storedHash.empty() && bcrypt::validatePassword(password, storedHash)) {
            loginSuccess = true;
        }

        if (loginSuccess) {
            const string sessionId = createSessionId();
            sessions.create(sessionId, userId);
            res.set_header("Set-Cookie",
                           "scc_session=" + sessionId +
                           "; Path=/; Max-Age=28800; HttpOnly; SameSite=Lax");
            Liteqry db(config.databasePath);
            auto loggedInUser = db.query("SELECT role FROM users WHERE id = ?;", {userId});
            const string role = loggedInUser.next() ? loggedInUser.at("role") : "";
            res.set_redirect(role == "customer" ? "/store" : "/dashboard", 302);
        } else {
            nlohmann::json errorData;
            errorData["error"] = "Invalid username or password!";
            string html = env.render_file("login.html", errorData);
            res.set_content(html, "text/html; charset=UTF-8");
        }
    }, true);
    // 3. Logout
    safeRoute(svr, "/logout", [&](const httplib::Request& req, httplib::Response& res) {
        const auto sessionId = getCookie(req, "scc_session");
        if (sessionId) {
            sessions.erase(*sessionId);
        }
        clearSessionCookie(res);
        res.set_redirect("/", 302);
    });
    // 4. Dashboard page (GET)
    safeRoute(svr, "/dashboard", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireSession(req, res, sessions, sessionsMutex, session) ||
            !requireRole(session, res, {"viewer", "manager", "admin"})) return;

        nlohmann::json data;
        data["error"] = "";
        data["username"] = session.username;
        data["role"] = session.role;
        data["csrf_token"] = session.csrfToken;

        Liteqry db(config.databasePath);
        auto entityRows = db.query(
            "SELECT COALESCE(et.entity, 'Unknown') AS entity_type, "
            "COUNT(*) AS qty "
            "FROM entities e "
            "LEFT JOIN entity_type et ON et.id = e.entity_type "
            "GROUP BY e.entity_type "
            "ORDER BY entity_type;");
        data["entity_breakdown"] = nlohmann::json::array();
        while (entityRows.next()) {
            nlohmann::json item;
            item["entity_type"] = entityRows.at("entity_type");
            item["qty"] = entityRows.at("qty");
            data["entity_breakdown"].push_back(item);
        }

        auto orderRows = db.query(
            "SELECT o.id AS order_id, "
            "COALESCE(e.name, 'Unknown customer') AS customer_name, "
            "o.status, "
            "printf('%.2f', COALESCE(SUM(oi.quantity * oi.unit_price), 0)) AS order_total "
            "FROM orders o "
            "LEFT JOIN entities e ON e.id = o.entity_id "
            "LEFT JOIN order_items oi ON oi.order_id = o.id "
            "GROUP BY o.id "
            "ORDER BY o.created_at DESC, o.id DESC "
            "LIMIT 5;");
        data["recent_orders"] = nlohmann::json::array();
        while (orderRows.next()) {
            nlohmann::json item;
            item["order_id"] = orderRows.at("order_id");
            item["customer_name"] = orderRows.at("customer_name");
            item["status"] = orderRows.at("status");
            item["order_total"] = orderRows.at("order_total");
            data["recent_orders"].push_back(item);
        }

        string html = env.render_file("dashboard.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 5. Product catalog (GET; all authenticated roles may view)
    safeRoute(svr, "/products-view", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireSession(req, res, sessions, sessionsMutex, session) ||
            !requireRole(session, res, {"viewer", "manager", "admin"})) return;

        const std::vector<string> sortableColumns = {
            "id", "name", "sku", "price", "stock_quantity", "created_at"};
        string sortBy = req.has_param("sort_by") ? req.get_param_value("sort_by") : "id";
        string order = req.has_param("order") ? req.get_param_value("order") : "ASC";

        bool validSort = false;
        for (const auto& column : sortableColumns) {
            if (sortBy == column) {
                validSort = true;
                break;
            }
        }
        if (!validSort) sortBy = "id";
        if (order != "ASC" && order != "DESC") order = "ASC";

        Liteqry db(config.databasePath);
        auto rows = db.query(
            "SELECT id, name, sku, printf('%.2f', price) AS price, "
            "stock_quantity, created_at FROM products ORDER BY " + sortBy + " " + order + ";");

        nlohmann::json data;
        data["username"] = session.username;
        data["role"] = session.role;
        data["csrf_token"] = session.csrfToken;
        data["can_restock"] = session.role == "admin" || session.role == "manager";
        data["columns"] = sortableColumns;
        data["current_sort"] = sortBy;
        data["current_order"] = order;
        data["next_order"] = order == "ASC" ? "DESC" : "ASC";
        data["rows"] = nlohmann::json::array();

        while (rows.next()) {
            nlohmann::json row;
            for (const auto& column : sortableColumns) {
                row[column] = rows.at(column);
            }
            data["rows"].push_back(row);
        }
        data["product_count"] = data["rows"].size();

        string html = env.render_file("products.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 6. Business entity registry (GET; all authenticated roles may view)
    safeRoute(svr, "/entities-view", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireSession(req, res, sessions, sessionsMutex, session) ||
            !requireRole(session, res, {"viewer", "manager", "admin"})) return;

        const std::vector<string> sortableColumns = {
            "id", "entity_type", "name", "email", "created_at"};
        string sortBy = req.has_param("sort_by") ? req.get_param_value("sort_by") : "id";
        string order = req.has_param("order") ? req.get_param_value("order") : "ASC";

        bool validSort = false;
        for (const auto& column : sortableColumns) {
            if (sortBy == column) {
                validSort = true;
                break;
            }
        }
        if (!validSort) sortBy = "id";
        if (order != "ASC" && order != "DESC") order = "ASC";

        const string orderBy = sortBy == "entity_type" ? "entity_type" : "e." + sortBy;

        Liteqry db(config.databasePath);
        auto rows = db.query(
            "SELECT e.id, COALESCE(et.entity, 'Unknown') AS entity_type, "
            "e.name, e.email, e.created_at "
            "FROM entities e LEFT JOIN entity_type et ON et.id = e.entity_type "
            "ORDER BY " + orderBy + " " + order + ";");

        nlohmann::json data;
        data["username"] = session.username;
        data["role"] = session.role;
        data["csrf_token"] = session.csrfToken;
        data["columns"] = sortableColumns;
        data["current_sort"] = sortBy;
        data["current_order"] = order;
        data["next_order"] = order == "ASC" ? "DESC" : "ASC";
        data["rows"] = nlohmann::json::array();

        while (rows.next()) {
            nlohmann::json row;
            for (const auto& column : sortableColumns) {
                row[column] = rows.at(column);
            }
            data["rows"].push_back(row);
        }
        data["entity_count"] = data["rows"].size();

        string html = env.render_file("entities.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 7. Orders list (GET; all authenticated roles may view)
    safeRoute(svr, "/orders-view", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireSession(req, res, sessions, sessionsMutex, session) ||
            !requireRole(session, res, {"viewer", "manager", "admin"})) return;

        int lookupOrderId = 0;
        const bool hasLookup = req.has_param("order_id");
        if (hasLookup && !parseInteger(req.get_param_value("order_id"), lookupOrderId, 1)) {
            res.status = 400;
            res.set_content("Invalid order number", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        string orderSql = string(
            "SELECT o.id AS order_id, COALESCE(e.name, 'Unknown customer') AS customer_name, "
            "o.status, o.created_at, "
            "printf('%.2f', COALESCE(SUM(oi.quantity * oi.unit_price), 0)) AS order_total "
            "FROM orders o LEFT JOIN entities e ON e.id = o.entity_id "
            "LEFT JOIN order_items oi ON oi.order_id = o.id ") +
            (hasLookup ? "WHERE o.id = ? " : "") +
            "GROUP BY o.id ORDER BY o.created_at DESC, o.id DESC;";
        const std::vector<string> lookupParams = hasLookup ?
            std::vector<string>{std::to_string(lookupOrderId)} : std::vector<string>{};
        auto orderRows = db.query(orderSql, lookupParams);

        nlohmann::json data;
        data["username"] = session.username;
        data["role"] = session.role;
        data["csrf_token"] = session.csrfToken;
        data["search_order_id"] = hasLookup ? std::to_string(lookupOrderId) : "";
        data["orders"] = nlohmann::json::array();
        data["items"] = nlohmann::json::array();
        data["has_orders"] = false;
        while (orderRows.next()) {
            nlohmann::json order;
            order["order_id"] = orderRows.at("order_id");
            order["customer_name"] = orderRows.at("customer_name");
            order["status"] = orderRows.at("status");
            order["created_at"] = orderRows.at("created_at");
            order["order_total"] = orderRows.at("order_total");
            data["orders"].push_back(order);
            data["has_orders"] = true;
        }

        string itemSql = string(
            "SELECT oi.order_id, p.name AS product_name, p.sku, oi.quantity, "
            "printf('%.2f', oi.unit_price) AS unit_price, "
            "printf('%.2f', oi.quantity * oi.unit_price) AS row_total "
            "FROM order_items oi LEFT JOIN products p ON p.id = oi.product_id ") +
            (hasLookup ? "WHERE oi.order_id = ? " : "") +
            "ORDER BY oi.order_id DESC, oi.id ASC;";
        auto itemRows = db.query(itemSql, lookupParams);
        while (itemRows.next()) {
            nlohmann::json item;
            item["order_id"] = itemRows.at("order_id");
            item["product_name"] = itemRows.at("product_name");
            item["sku"] = itemRows.at("sku");
            item["quantity"] = itemRows.at("quantity");
            item["unit_price"] = itemRows.at("unit_price");
            item["row_total"] = itemRows.at("row_total");
            data["items"].push_back(item);
        }

        string html = env.render_file("orders.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 8. Order detail (GET; all authenticated roles may view)
    safeRoute(svr, "/orders/(\\d+)", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireSession(req, res, sessions, sessionsMutex, session)) return;
        if (session.role == "customer") {
            // Customer ownership is enforced by the order query below.
        } else if (!requireRole(session, res, {"viewer", "manager", "admin"})) {
            return;
        }

        const string orderId = req.matches[1].str();
        Liteqry db(config.databasePath);
        const string orderOwnership = session.role == "customer" ?
            " AND o.user_id = ?" : "";
        const std::vector<string> orderParams = session.role == "customer" ?
            std::vector<string>{orderId, session.userId} : std::vector<string>{orderId};
        auto orderRows = db.query(
            "SELECT o.id AS order_id, COALESCE(e.name, 'Unknown customer') AS customer_name, "
            "o.status, o.created_at, "
            "printf('%.2f', COALESCE(SUM(oi.quantity * oi.unit_price), 0)) AS order_total "
            "FROM orders o LEFT JOIN entities e ON e.id = o.entity_id "
            "LEFT JOIN order_items oi ON oi.order_id = o.id "
            "WHERE o.id = ?" + orderOwnership + " GROUP BY o.id;",
            orderParams);

        if (!orderRows.next()) {
            res.status = 404;
            res.set_content("Order not found", "text/plain; charset=UTF-8");
            return;
        }

        nlohmann::json data;
        data["order"]["order_id"] = orderRows.at("order_id");
        data["order"]["customer_name"] = orderRows.at("customer_name");
        data["order"]["status"] = orderRows.at("status");
        data["order"]["created_at"] = orderRows.at("created_at");
        data["order"]["order_total"] = orderRows.at("order_total");
        data["items"] = nlohmann::json::array();
        data["back_url"] = "/orders-view";
        data["back_label"] = "← All orders";
        data["username"] = session.username;
        data["role"] = session.role;
        data["csrf_token"] = session.csrfToken;
        data["read_only"] = session.role == "viewer";

        auto itemRows = db.query(
            "SELECT p.name AS product_name, p.sku, oi.quantity, "
            "printf('%.2f', oi.unit_price) AS unit_price, "
            "printf('%.2f', oi.quantity * oi.unit_price) AS row_total "
            "FROM order_items oi LEFT JOIN products p ON p.id = oi.product_id "
            "WHERE oi.order_id = ? ORDER BY oi.id ASC;",
            {orderId});
        while (itemRows.next()) {
            nlohmann::json item;
            item["product_name"] = itemRows.at("product_name");
            item["sku"] = itemRows.at("sku");
            item["quantity"] = itemRows.at("quantity");
            item["unit_price"] = itemRows.at("unit_price");
            item["row_total"] = itemRows.at("row_total");
            data["items"].push_back(item);
        }

        string html = env.render_file("order_detail.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 10. Internal checkout page (GET; all authenticated roles may view)
    safeRoute(svr, "/admin/checkout", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireSession(req, res, sessions, sessionsMutex, session) ||
            !requireRole(session, res, {"viewer", "manager", "admin"})) return;

        Liteqry db(config.databasePath);
        auto customerRows = db.query(
            "SELECT e.id, e.name, COALESCE(et.entity, 'Unknown') AS entity_type "
            "FROM entities e LEFT JOIN entity_type et ON et.id = e.entity_type "
            "ORDER BY e.name ASC;");
        auto productRows = db.query(
            "SELECT id, name, printf('%.2f', price) AS price, stock_quantity "
            "FROM products ORDER BY name ASC;");

        nlohmann::json data;
        data["username"] = session.username;
        data["role"] = session.role;
        data["csrf_token"] = session.csrfToken;
        data["customers"] = nlohmann::json::array();
        data["products"] = nlohmann::json::array();
        while (customerRows.next()) {
            nlohmann::json customer;
            customer["id"] = customerRows.at("id");
            customer["name"] = customerRows.at("name");
            customer["entity_type"] = customerRows.at("entity_type");
            data["customers"].push_back(customer);
        }
        while (productRows.next()) {
            nlohmann::json product;
            product["id"] = productRows.at("id");
            product["name"] = productRows.at("name");
            product["price"] = productRows.at("price");
            product["stock_quantity"] = productRows.at("stock_quantity");
            data["products"].push_back(product);
        }

        string html = env.render_file("checkout.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 10. Create order (POST; managers and administrators only)
    safeRoute(svr, "/admin/checkout/create", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireSession(req, res, sessions, sessionsMutex, session)) return;
        if (!requireRole(session, res, {"manager", "admin"}) ||
            !requireCsrfToken(req, res, session)) return;

        int entityId = 0;
        const auto productIds = req.get_param_values("product_id");
        const auto quantities = req.get_param_values("quantity");
        if (!parseInteger(req.get_param_value("entity_id"), entityId, 1) ||
            productIds.empty() || productIds.size() != quantities.size()) {
            res.status = 400;
            res.set_content("Invalid order data", "text/plain; charset=UTF-8");
            return;
        }

        struct SelectedProduct {
            int id;
            int quantity;
            string unitPrice;
        };
        std::vector<SelectedProduct> selectedProducts;
        Liteqry db(config.databasePath);

        for (std::size_t i = 0; i < productIds.size(); ++i) {
            int productId = 0;
            int quantity = 0;
            if (!parseInteger(productIds[i], productId, 1) ||
                !parseInteger(quantities[i], quantity, 1)) {
                res.status = 400;
                res.set_content("Invalid order data", "text/plain; charset=UTF-8");
                return;
            }

            for (const auto& selected : selectedProducts) {
                if (selected.id == productId) {
                    res.status = 400;
                    res.set_content("A product may only appear once per order", "text/plain; charset=UTF-8");
                    return;
                }
            }

            auto productRows = db.query(
                "SELECT printf('%.2f', price) AS unit_price, stock_quantity "
                "FROM products WHERE id = ?;",
                {std::to_string(productId)});
            if (!productRows.next()) {
                res.status = 400;
                res.set_content("Product not found", "text/plain; charset=UTF-8");
                return;
            }

            int stockQuantity = 0;
            if (!parseInteger(productRows.at("stock_quantity"), stockQuantity, 0) ||
                quantity > stockQuantity) {
                res.status = 400;
                res.set_content("Insufficient product stock", "text/plain; charset=UTF-8");
                return;
            }
            selectedProducts.push_back({productId, quantity, productRows.at("unit_price")});
        }

        try {
            db.execute("BEGIN TRANSACTION;");
            db.execute(
                "INSERT INTO orders (entity_id, user_id, status) VALUES (?, ?, 'COMPLETED');",
                {std::to_string(entityId), session.userId});
            string orderId;
            {
                auto orderIdRows = db.query("SELECT last_insert_rowid() AS order_id;");
                if (!orderIdRows.next()) throw std::runtime_error("Could not create order");
                orderId = orderIdRows.at("order_id");
            }

            for (const auto& selected : selectedProducts) {
                db.execute(
                    "INSERT INTO order_items (order_id, product_id, quantity, unit_price) "
                    "VALUES (?, ?, ?, ?);",
                    {orderId, std::to_string(selected.id), std::to_string(selected.quantity), selected.unitPrice});
                if (db.execute(
                        "UPDATE products SET stock_quantity = stock_quantity - ? "
                        "WHERE id = ? AND stock_quantity >= ?;",
                        {std::to_string(selected.quantity), std::to_string(selected.id), std::to_string(selected.quantity)}) != 1) {
                    throw std::runtime_error("Product stock changed; please try again");
                }
            }
            db.execute("COMMIT;");
            res.set_redirect("/orders/" + orderId, 303);
        } catch (...) {
            try { db.execute("ROLLBACK;"); } catch (...) {}
            throw;
        }
    }, true);

    // 11. Full order refund (POST; managers and administrators only)
    safeRoute(svr, "/orders/(\\d+)/refund", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireSession(req, res, sessions, sessionsMutex, session)) return;
        if (!requireRole(session, res, {"manager", "admin"}) ||
            !requireCsrfToken(req, res, session)) return;

        const string reason = trim(req.get_param_value("reason"));
        if (reason.empty() || reason.size() > 255) {
            res.status = 400;
            res.set_content("A refund reason between 1 and 255 characters is required",
                           "text/plain; charset=UTF-8");
            return;
        }

        const string orderId = req.matches[1].str();
        string orderStatus;
        string refundAmount;
        struct RefundItem {
            string productId;
            string quantity;
            string unitPrice;
        };
        std::vector<RefundItem> refundItems;
        {
            Liteqry readDb(config.databasePath);
            auto orderRows = readDb.query(
                "SELECT o.status, printf('%.2f', COALESCE(SUM(oi.quantity * oi.unit_price), 0)) AS amount "
                "FROM orders o LEFT JOIN order_items oi ON oi.order_id = o.id "
                "WHERE o.id = ? GROUP BY o.id;",
                {orderId});
            if (!orderRows.next()) {
                res.status = 404;
                res.set_content("Order not found", "text/plain; charset=UTF-8");
                return;
            }
            orderStatus = orderRows.at("status");
            refundAmount = orderRows.at("amount");

            auto existingRefund = readDb.query(
                "SELECT id FROM order_refunds WHERE order_id = ?;", {orderId});
            if (existingRefund.next()) {
                res.status = 409;
                res.set_content("Order has already been refunded", "text/plain; charset=UTF-8");
                return;
            }

            auto itemRows = readDb.query(
                "SELECT product_id, quantity, printf('%.2f', unit_price) AS unit_price "
                "FROM order_items WHERE order_id = ? ORDER BY id ASC;",
                {orderId});
            while (itemRows.next()) {
                refundItems.push_back({
                    itemRows.at("product_id"),
                    itemRows.at("quantity"),
                    itemRows.at("unit_price")});
            }
        }
        if (orderStatus != "COMPLETED") {
            res.status = 400;
            res.set_content("Only completed orders can be refunded", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        try {
            db.execute("BEGIN TRANSACTION;");
            db.execute(
                "INSERT INTO order_refunds (order_id, refunded_by, reason, amount) "
                "VALUES (?, ?, ?, ?);",
                {orderId, session.userId, reason, refundAmount});
            auto refundIdRows = db.query("SELECT last_insert_rowid() AS refund_id;");
            if (!refundIdRows.next()) throw std::runtime_error("Could not create refund");
            const string refundId = refundIdRows.at("refund_id");

            for (const auto& item : refundItems) {
                db.execute(
                    "INSERT INTO order_refund_items "
                    "(refund_id, order_item_id, quantity, unit_price) "
                    "SELECT ?, id, quantity, unit_price FROM order_items "
                    "WHERE order_id = ? AND product_id = ?;",
                    {refundId, orderId, item.productId});
                db.execute(
                    "UPDATE products SET stock_quantity = stock_quantity + ? WHERE id = ?;",
                    {item.quantity, item.productId});
            }

            if (db.execute(
                    "UPDATE orders SET status = 'REFUNDED' "
                    "WHERE id = ? AND status = 'COMPLETED';",
                    {orderId}) != 1) {
                throw std::runtime_error("Order status changed; please try again");
            }
            db.execute("COMMIT;");
            res.set_redirect("/orders/" + orderId, 303);
        } catch (...) {
            try { db.execute("ROLLBACK;"); } catch (...) {}
            throw;
        }
    }, true);

    // 12. User administration (GET; administrators only)
    safeRoute(svr, "/users-view", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireAdmin(req, res, sessions, sessionsMutex, session)) return;

        Liteqry db(config.databasePath);
        auto rows = db.query(
            "SELECT id, username, email, role, created_at FROM users ORDER BY username ASC;");
        const std::vector<string> columns = {"id", "username", "email", "role", "created_at"};

        nlohmann::json data;
        data["username"] = session.username;
        data["role"] = session.role;
        data["csrf_token"] = session.csrfToken;
        data["columns"] = columns;
        data["rows"] = nlohmann::json::array();
        while (rows.next()) {
            nlohmann::json row;
            for (const auto& column : columns) row[column] = rows.at(column);
            data["rows"].push_back(row);
        }

        string html = env.render_file("users.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });

    // 13. Create user (POST; administrators only)
    safeRoute(svr, "/users/create", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireAdmin(req, res, sessions, sessionsMutex, session)) return;

        const string username = trim(req.get_param_value("username"));
        const string email = trim(req.get_param_value("email"));
        const string role = trim(req.get_param_value("role"));
        const string password = req.get_param_value("password");
        if (username.empty() || email.empty() || !isValidRole(role) || password.size() < 8) {
            res.status = 400;
            res.set_content("Invalid user data", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?);",
            {username, email, bcrypt::generateHash(password), role});
        res.set_redirect("/users-view", 303);
    }, true);

    // 14. Update user (POST; administrators only)
    safeRoute(svr, "/users/update", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireAdmin(req, res, sessions, sessionsMutex, session)) return;

        int id = 0;
        const string username = trim(req.get_param_value("username"));
        const string email = trim(req.get_param_value("email"));
        const string role = trim(req.get_param_value("role"));
        const string password = req.get_param_value("password");
        if (!parseInteger(req.get_param_value("id"), id, 1) || username.empty() ||
            email.empty() || !isValidRole(role) || (!password.empty() && password.size() < 8)) {
            res.status = 400;
            res.set_content("Invalid user data", "text/plain; charset=UTF-8");
            return;
        }

        string previousRole;
        {
            Liteqry readDb(config.databasePath);
            auto existingUser = readDb.query("SELECT role FROM users WHERE id = ?;", {std::to_string(id)});
            if (!existingUser.next()) {
                res.status = 404;
                res.set_content("User not found", "text/plain; charset=UTF-8");
                return;
            }
            previousRole = existingUser.at("role");
        }
        if (previousRole == "admin" && role != "admin") {
            Liteqry readDb(config.databasePath);
            auto adminCount = readDb.query("SELECT COUNT(*) AS count FROM users WHERE role = 'admin';");
            if (adminCount.next() && adminCount.at("count") == "1") {
                res.status = 409;
                res.set_content("The last administrator cannot be demoted", "text/plain; charset=UTF-8");
                return;
            }
        }

        Liteqry db(config.databasePath);
        if (password.empty()) {
            db.execute(
                "UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?;",
                {username, email, role, std::to_string(id)});
        } else {
            db.execute(
                "UPDATE users SET username = ?, email = ?, password_hash = ?, role = ? WHERE id = ?;",
                {username, email, bcrypt::generateHash(password), role, std::to_string(id)});
        }

        res.set_redirect("/users-view", 303);
    }, true);

    // 15. Delete user (POST; administrators only)
    safeRoute(svr, "/users/delete/(\\d+)", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireAdmin(req, res, sessions, sessionsMutex, session)) return;

        const string userId = req.matches[1].str();
        if (userId == session.userId) {
            res.status = 409;
            res.set_content("You cannot delete your own account", "text/plain; charset=UTF-8");
            return;
        }

        string targetRole;
        {
            Liteqry readDb(config.databasePath);
            auto targetUser = readDb.query("SELECT role FROM users WHERE id = ?;", {userId});
            if (!targetUser.next()) {
                res.status = 404;
                res.set_content("User not found", "text/plain; charset=UTF-8");
                return;
            }
            targetRole = targetUser.at("role");
        }
        if (targetRole == "admin") {
            Liteqry readDb(config.databasePath);
            auto adminCount = readDb.query("SELECT COUNT(*) AS count FROM users WHERE role = 'admin';");
            if (adminCount.next() && adminCount.at("count") == "1") {
                res.status = 409;
                res.set_content("The last administrator cannot be deleted", "text/plain; charset=UTF-8");
                return;
            }
        }

        Liteqry db(config.databasePath);
        db.execute("DELETE FROM users WHERE id = ?;", {userId});
        sessions.eraseUser(userId);
        res.set_redirect("/users-view", 303);
    }, true);

    // 16. Product management (POST; administrators only)
    safeRoute(svr, "/products/create", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireAdmin(req, res, sessions, sessionsMutex, session)) return;

        const string name = trim(req.get_param_value("name"));
        const string sku = trim(req.get_param_value("sku"));
        string price;
        int stockQuantity = 0;
        if (name.empty() || sku.empty() ||
            !parseMoney(req.get_param_value("price"), price) ||
            !parseInteger(req.get_param_value("stock_quantity"), stockQuantity, 0)) {
            res.status = 400;
            res.set_content("Invalid product data", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        db.execute(
            "INSERT INTO products (name, sku, price, stock_quantity) VALUES (?, ?, ?, ?);",
            {name, sku, price, std::to_string(stockQuantity)});
        res.set_redirect("/products-view", 303);
    }, true);

    safeRoute(svr, "/products/update", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireAdmin(req, res, sessions, sessionsMutex, session)) return;

        int id = 0;
        int stockQuantity = 0;
        string price;
        const string name = trim(req.get_param_value("name"));
        const string sku = trim(req.get_param_value("sku"));
        if (!parseInteger(req.get_param_value("id"), id, 1) || name.empty() || sku.empty() ||
            !parseMoney(req.get_param_value("price"), price) ||
            !parseInteger(req.get_param_value("stock_quantity"), stockQuantity, 0)) {
            res.status = 400;
            res.set_content("Invalid product data", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        db.execute(
            "UPDATE products SET name = ?, sku = ?, price = ?, stock_quantity = ? WHERE id = ?;",
            {name, sku, price, std::to_string(stockQuantity), std::to_string(id)});
        res.set_redirect("/products-view", 303);
    }, true);

    safeRoute(svr, "/products/restock", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireManager(req, res, sessions, sessionsMutex, session)) return;

        int productId = 0;
        int quantity = 0;
        if (!parseInteger(req.get_param_value("id"), productId, 1) ||
            !parseInteger(req.get_param_value("quantity"), quantity, 1)) {
            res.status = 400;
            res.set_content("Invalid restock data", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        if (db.execute(
                "UPDATE products SET stock_quantity = stock_quantity + ? WHERE id = ?;",
                {std::to_string(quantity), std::to_string(productId)}) != 1) {
            res.status = 404;
            res.set_content("Product not found", "text/plain; charset=UTF-8");
            return;
        }
        res.set_redirect("/products-view", 303);
    }, true);

    safeRoute(svr, "/products/delete/(\\d+)", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireAdmin(req, res, sessions, sessionsMutex, session)) return;

        Liteqry db(config.databasePath);
        db.execute("DELETE FROM products WHERE id = ?;", {req.matches[1].str()});
        res.set_redirect("/products-view", 303);
    }, true);

    // 8. Entity management (POST; administrators only)
    safeRoute(svr, "/entities/create", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireAdmin(req, res, sessions, sessionsMutex, session)) return;

        int entityType = 0;
        const string name = trim(req.get_param_value("name"));
        const string email = trim(req.get_param_value("email"));
        if (!parseEntityType(req.get_param_value("entity_type"), entityType) || name.empty()) {
            res.status = 400;
            res.set_content("Invalid entity data", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        db.execute(
            "INSERT INTO entities (entity_type, name, email) VALUES (?, ?, ?);",
            {std::to_string(entityType), name, email});
        res.set_redirect("/entities-view", 303);
    }, true);

    safeRoute(svr, "/entities/update", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireAdmin(req, res, sessions, sessionsMutex, session)) return;

        int id = 0;
        int entityType = 0;
        const string name = trim(req.get_param_value("name"));
        const string email = trim(req.get_param_value("email"));
        if (!parseInteger(req.get_param_value("id"), id, 1) ||
            !parseEntityType(req.get_param_value("entity_type"), entityType) || name.empty()) {
            res.status = 400;
            res.set_content("Invalid entity data", "text/plain; charset=UTF-8");
            return;
        }

        Liteqry db(config.databasePath);
        db.execute(
            "UPDATE entities SET entity_type = ?, name = ?, email = ? WHERE id = ?;",
            {std::to_string(entityType), name, email, std::to_string(id)});
        res.set_redirect("/entities-view", 303);
    }, true);

    safeRoute(svr, "/entities/delete/(\\d+)", [&](const httplib::Request& req, httplib::Response& res) {
        UserSession session;
        if (!requireAdmin(req, res, sessions, sessionsMutex, session)) return;

        Liteqry db(config.databasePath);
        db.execute("DELETE FROM entities WHERE id = ?;", {req.matches[1].str()});
        res.set_redirect("/entities-view", 303);
    }, true);

    print("Server running at http://localhost:8080/");
    svr.listen(config.host, config.port);
}
//--------------------------------------------------------------------------------------------------
