//--------------------------------------------------------------------------------------------------
#include <iostream>
//using namespace std;
using std::string;
//--------------------------------------------------------------------------------------------------
#define _WIN32_WINNT 0x0A00
//#define CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_NO_OPENSSL
//--------------------------------------------------------------------------------------------------
#include "httplib.h"
#include "inja/inja.hpp"
#include "nlohmann/json.hpp"
#include "sqlite/sqlite3.h"
#include "bcrypt/scc_bcrypt.h"
#include "Liteqry.h"
#include <fstream>
#include <functional>
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
    string databasePath = "data/sccrest.db";
    string templatesPath = "templates/";
    string staticPath = "static/";
};

static string trim(const string& value) {
    const string whitespace = " \t\r\n";
    const std::size_t first = value.find_first_not_of(whitespace);
    if (first == string::npos) return "";
    const std::size_t last = value.find_last_not_of(whitespace);
    return value.substr(first, last - first + 1);
}

AppConfig iniConfig(const string& iniPath = "Testhttplib.ini") {
    AppConfig config;
    std::ifstream file(iniPath);

    if (!file.is_open()) {
        print("Configuration file not found: " + iniPath + ". Using defaults.");
        return config;
    }

    string section;
    string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;

        if (line.front() == '[' && line.back() == ']') {
            section = trim(line.substr(1, line.size() - 2));
            continue;
        }

        const std::size_t separator = line.find('=');
        if (separator == string::npos) continue;

        const string key = trim(line.substr(0, separator));
        const string value = trim(line.substr(separator + 1));

        if (section == "server" && key == "host") config.host = value;
        else if (section == "server" && key == "port") config.port = std::stoi(value);
        else if (section == "paths" && key == "database") config.databasePath = value;
        else if (section == "paths" && key == "templates") config.templatesPath = value;
        else if (section == "paths" && key == "static") config.staticPath = value;
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
int main() {
    const AppConfig config = iniConfig();
    httplib::Server svr;
    if (!svr.set_mount_point("/static", config.staticPath)) {
        throw std::runtime_error("Could not mount static directory");
    }
    inja::Environment env(config.templatesPath);
    // 1. Root login page (GET)
    safeRoute(svr, "/", [&](const httplib::Request& req, httplib::Response& res) {
        nlohmann::json data;
        data["error"] = "";
        string html = env.render_file("login.html", data);
        res.set_content(html, "text/html; charset=UTF-8");
    });
    // 2. Login handler (POST) - Notice the 'true' at the end for POST requests!
    safeRoute(svr, "/login", [&](const httplib::Request& req, httplib::Response& res) {
        string username = req.get_param_value("username");
        string password = req.get_param_value("password");

        Liteqry db(config.databasePath);
        auto result = db.query(
            "SELECT password_hash FROM users WHERE username = ?;",
            {username});
        string storedHash;
        if (result.next()) {
            storedHash = result.at("password_hash");
        }

        bool loginSuccess = false;
        if (!storedHash.empty() && bcrypt::validatePassword(password, storedHash)) {
            loginSuccess = true;
        }

        if (loginSuccess) {
            res.set_redirect("/dashboard", 302);
        } else {
            nlohmann::json errorData;
            errorData["error"] = "Invalid username or password!";
            string html = env.render_file("login.html", errorData);
            res.set_content(html, "text/html; charset=UTF-8");
        }
    }, true);
    // 3. Dashboard page (GET)
    safeRoute(svr, "/dashboard", [&](const httplib::Request& req, httplib::Response& res) {
        nlohmann::json data;
        data["error"] = "";

        // The login route currently redirects without a session cookie, so use
        // the optional query values when supplied and safe display defaults
        // otherwise. These values are only used to render the dashboard.
        data["username"] = req.has_param("username") ? req.get_param_value("username") : "Guest";
        data["role"] = req.has_param("role") ? req.get_param_value("role") : "viewer";

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

    print("Server running at http://localhost:8080/");
    svr.listen(config.host, config.port);
}
//--------------------------------------------------------------------------------------------------
