//--------------------------------------------------------------------------------------------------
#include "Liteqry.h"
#include <stdexcept>
#include <utility>
//--------------------------------------------------------------------------------------------------
Liteqry::Liteqry(const std::string& dbPath) : db_(nullptr) {
    if (sqlite3_open(dbPath.c_str(), &db_) != SQLITE_OK) {
        const std::string message = db_ ? sqlite3_errmsg(db_) : "unknown error";
        if (db_) sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("Could not open database: " + message);
    }
}
//--------------------------------------------------------------------------------------------------
Liteqry::~Liteqry() { if (db_) sqlite3_close(db_); }
//--------------------------------------------------------------------------------------------------
bool Liteqry::isOpen() const { return db_ != nullptr; }

Liteqry::ResultSet::ResultSet() noexcept
    : statement_(nullptr), eof_(true), hasRow_(false) {}

Liteqry::ResultSet::ResultSet(sqlite3_stmt* statement)
    : statement_(statement), eof_(false), hasRow_(false) {}

Liteqry::ResultSet::~ResultSet() { close(); }

Liteqry::ResultSet::ResultSet(ResultSet&& other) noexcept
    : statement_(other.statement_), eof_(other.eof_), hasRow_(other.hasRow_) {
    other.statement_ = nullptr;
    other.eof_ = true;
    other.hasRow_ = false;
}

Liteqry::ResultSet& Liteqry::ResultSet::operator=(ResultSet&& other) noexcept {
    if (this != &other) {
        close();
        statement_ = other.statement_;
        eof_ = other.eof_;
        hasRow_ = other.hasRow_;
        other.statement_ = nullptr;
        other.eof_ = true;
        other.hasRow_ = false;
    }
    return *this;
}

void Liteqry::ResultSet::close() noexcept {
    if (statement_) sqlite3_finalize(statement_);
    statement_ = nullptr;
    eof_ = true;
    hasRow_ = false;
}

bool Liteqry::ResultSet::next() {
    if (!statement_ || eof_) return false;
    const int result = sqlite3_step(statement_);
    if (result == SQLITE_ROW) {
        hasRow_ = true;
        return true;
    }
    if (result == SQLITE_DONE) {
        eof_ = true;
        hasRow_ = false;
        return false;
    }
    throw std::runtime_error("Could not read query result");
}

bool Liteqry::ResultSet::eof() const { return eof_; }

int Liteqry::ResultSet::columnIndex(const std::string& name) const {
    if (!statement_) throw std::runtime_error("Result set is closed");
    for (int i = 0; i < sqlite3_column_count(statement_); ++i) {
        if (name == sqlite3_column_name(statement_, i)) return i;
    }
    throw std::runtime_error("Column not found: " + name);
}

std::string Liteqry::ResultSet::fieldByIndex(int index) const {
    if (!hasRow_) throw std::runtime_error("Result set is not positioned on a row");
    if (index < 0 || index >= sqlite3_column_count(statement_))
        throw std::runtime_error("Column index out of range");
    const unsigned char* value = sqlite3_column_text(statement_, index);
    return value ? reinterpret_cast<const char*>(value) : "";
}

std::string Liteqry::ResultSet::at(const std::string& name) const {
    return fieldByIndex(columnIndex(name));
}

bool Liteqry::ResultSet::isNull(const std::string& name) const {
    if (!hasRow_) throw std::runtime_error("Result set is not positioned on a row");
    return sqlite3_column_type(statement_, columnIndex(name)) == SQLITE_NULL;
}

int Liteqry::ResultSet::columnCount() const {
    return statement_ ? sqlite3_column_count(statement_) : 0;
}
//--------------------------------------------------------------------------------------------------
sqlite3_stmt* Liteqry::prepare(const std::string& sql, const std::vector<std::string>& params) const {
    if (!db_) throw std::runtime_error("Database is not open");
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Could not prepare SQL: " + std::string(sqlite3_errmsg(db_)));
    }
    try { bindParams(statement, params); }
    catch (...) { sqlite3_finalize(statement); throw; }
    return statement;
}
//--------------------------------------------------------------------------------------------------
void Liteqry::bindParams(sqlite3_stmt* statement, const std::vector<std::string>& params) {
    for (std::size_t i = 0; i < params.size(); ++i) {
        if (sqlite3_bind_text(statement, static_cast<int>(i + 1), params[i].c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
            throw std::runtime_error("Could not bind SQL parameter");
        }
    }
}
//--------------------------------------------------------------------------------------------------
Liteqry::ResultSet Liteqry::query(const std::string& sql, const std::vector<std::string>& params) const {
    sqlite3_stmt* statement = prepare(sql, params);
    return ResultSet(statement);
}
//--------------------------------------------------------------------------------------------------
int Liteqry::execute(const std::string& sql, const std::vector<std::string>& params) const {
    sqlite3_stmt* statement = prepare(sql, params);
    try {
        if (sqlite3_step(statement) != SQLITE_DONE) {
            throw std::runtime_error("Could not execute statement: " + std::string(sqlite3_errmsg(db_)));
        }
    } catch (...) { sqlite3_finalize(statement); throw; }
    sqlite3_finalize(statement);
    return sqlite3_changes(db_);
}
//--------------------------------------------------------------------------------------------------
