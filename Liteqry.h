//--------------------------------------------------------------------------------------------------
#ifndef LITEQRY_H
#define LITEQRY_H

#include "third_party/sqlite/sqlite3.h"
#include <string>
#include <vector>
//--------------------------------------------------------------------------------------------------
class Liteqry {
public:
    class ResultSet {
    public:
        ResultSet() noexcept;
        ~ResultSet();
        ResultSet(const ResultSet&) = delete;
        ResultSet& operator=(const ResultSet&) = delete;
        ResultSet(ResultSet&& other) noexcept;
        ResultSet& operator=(ResultSet&& other) noexcept;

        bool next();
        bool eof() const;
        std::string at(const std::string& name) const;
        std::string fieldByIndex(int index) const;
        bool isNull(const std::string& name) const;
        int columnCount() const;

    private:
        friend class Liteqry;
        explicit ResultSet(sqlite3_stmt* statement);
        void close() noexcept;
        int columnIndex(const std::string& name) const;

        sqlite3_stmt* statement_;
        bool eof_;
        bool hasRow_;
    };

    explicit Liteqry(const std::string& dbPath);
    ~Liteqry();
    Liteqry(const Liteqry&) = delete;
    Liteqry& operator=(const Liteqry&) = delete;

    bool isOpen() const;
    ResultSet query(const std::string& sql, const std::vector<std::string>& params = {}) const;
    int execute(const std::string& sql, const std::vector<std::string>& params = {}) const;

private:
    sqlite3* db_;
    sqlite3_stmt* prepare(const std::string& sql, const std::vector<std::string>& params) const;
    static void bindParams(sqlite3_stmt* statement, const std::vector<std::string>& params);
};

#endif
//--------------------------------------------------------------------------------------------------
