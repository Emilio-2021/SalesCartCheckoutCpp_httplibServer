#pragma once

#include <mutex>
#include <optional>
#include <string>

struct UserSession {
    std::string userId;
    std::string username;
    std::string role;
    std::string csrfToken;
};

std::string createSessionId();

class SessionStore {
public:
    explicit SessionStore(const std::string& databasePath);

    void initialize();
    std::string create(const std::string& sessionId, const std::string& userId);
    std::optional<UserSession> find(const std::string& sessionId);
    void erase(const std::string& sessionId);
    void eraseUser(const std::string& userId);

private:
    std::string databasePath_;
    std::mutex mutex_;
};
