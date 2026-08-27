#include "session_store.h"

#include "Liteqry.h"

#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>

std::string createSessionId() {
    static std::random_device randomDevice;
    static std::mt19937_64 generator(randomDevice());
    static std::mutex generatorMutex;
    std::lock_guard<std::mutex> lock(generatorMutex);

    std::ostringstream token;
    for (int i = 0; i < 4; ++i) {
        token << std::hex << std::setw(16) << std::setfill('0') << generator();
    }
    return token.str();
}

SessionStore::SessionStore(const std::string& databasePath) : databasePath_(databasePath) {}

void SessionStore::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    Liteqry db(databasePath_);
    db.execute(
        "CREATE TABLE IF NOT EXISTS sessions ("
        "id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, "
        "csrf_token TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);");
    try {
        db.execute("ALTER TABLE sessions ADD COLUMN csrf_token TEXT;");
    } catch (...) {
        // The column already exists on an established database.
    }
    db.execute("DELETE FROM sessions;");
}

std::string SessionStore::create(const std::string& sessionId, const std::string& userId) {
    const std::string csrfToken = createSessionId();
    const auto now = std::chrono::system_clock::now();
    const auto nowSeconds = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    const auto expiresSeconds = nowSeconds + 8 * 60 * 60;

    std::lock_guard<std::mutex> lock(mutex_);
    Liteqry db(databasePath_);
    db.execute(
        "INSERT INTO sessions (id, user_id, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?);",
        {sessionId, userId, csrfToken, std::to_string(expiresSeconds), std::to_string(nowSeconds)});
    return csrfToken;
}

std::optional<UserSession> SessionStore::find(const std::string& sessionId) {
    const auto nowSeconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::lock_guard<std::mutex> lock(mutex_);
    Liteqry db(databasePath_);
    auto result = db.query(
        "SELECT s.user_id, u.username, u.role, s.csrf_token FROM sessions s "
        "JOIN users u ON u.id = s.user_id "
        "WHERE s.id = ? AND s.expires_at > ?;",
        {sessionId, std::to_string(nowSeconds)});
    if (!result.next()) return std::nullopt;
    return UserSession{result.at("user_id"), result.at("username"), result.at("role"), result.at("csrf_token")};
}

void SessionStore::erase(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    Liteqry db(databasePath_);
    db.execute("DELETE FROM sessions WHERE id = ?;", {sessionId});
}

void SessionStore::eraseUser(const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    Liteqry db(databasePath_);
    db.execute("DELETE FROM sessions WHERE user_id = ?;", {userId});
}
