#pragma once

#include <mutex>
#include <string>
#include <unordered_map>

struct CartSnapshot {
    std::string csrfToken;
    std::unordered_map<int, int> quantities;
};

class CartStore {
public:
    CartSnapshot getOrCreate(const std::string& cartId);
    bool hasValidCsrf(const std::string& cartId, const std::string& csrfToken);
    void setQuantity(const std::string& cartId, int productId, int quantity);
    void remove(const std::string& cartId, int productId);

private:
    std::unordered_map<std::string, CartSnapshot> carts_;
    std::mutex mutex_;
};
