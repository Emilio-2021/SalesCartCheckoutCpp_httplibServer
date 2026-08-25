#ifndef SCC_PASSWORD_BCRYPT_H
#define SCC_PASSWORD_BCRYPT_H

#include <string>

namespace bcrypt {

    std::string generateHash(const std::string & password , unsigned rounds = 10 );

    bool validatePassword(const std::string & password, const std::string & hash);

}

#endif // SCC_PASSWORD_BCRYPT_H
