#pragma once


#include <array>
#include <cwchar>
#include <openssl/rand.h>
#include <string>
#include <optional>
namespace MyMicro{
    class CryptMaster{
        private:
            static std::optional<std::string> SCryptHashCore(const char* password,
            std::size_t pLen, const char* salt, std::size_t sLen) noexcept;
        public:
            template <std::size_t N>
            static auto GenerateRandomArray() noexcept{
                std::array<char, N> result;
                RAND_priv_bytes(result.data(), N);
                return result;
            }
            static void GenerateRsaKey(std::string & out_pub_key, std::string & out_pri_key) noexcept;
            static std::optional<std::string> SCryptHash(const std::string& password, const std::string& salt) noexcept;
    };
}