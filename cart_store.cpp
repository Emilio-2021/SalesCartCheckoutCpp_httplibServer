#include "cart_store.h"

#include "session_store.h"

CartSnapshot CartStore::getOrCreate(const std::string& cartId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = carts_.find(cartId);
    if (found != carts_.end()) return found->second;

    CartSnapshot cart;
    cart.csrfToken = createSessionId();
    carts_[cartId] = cart;
    return cart;
}

bool CartStore::hasValidCsrf(const std::string& cartId, const std::string& csrfToken) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = carts_.find(cartId);
    return found != carts_.end() && !csrfToken.empty() &&
           found->second.csrfToken == csrfToken;
}

void CartStore::setQuantity(const std::string& cartId, int productId, int quantity) {
    std::lock_guard<std::mutex> lock(mutex_);
    carts_[cartId].quantities[productId] = quantity;
}

void CartStore::remove(const std::string& cartId, int productId) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = carts_.find(cartId);
    if (found != carts_.end()) found->second.quantities.erase(productId);
}

void CartStore::clear(const std::string& cartId) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = carts_.find(cartId);
    if (found != carts_.end()) found->second.quantities.clear();
}
