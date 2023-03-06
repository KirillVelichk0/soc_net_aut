#pragma once
#include <string_view>
#include <vector>
#include <array>
#include <cwchar>
#include <string>
#include <optional>
namespace MyMicro{
    class CryptMaster{
        private:
            static bool TryGenRandomArrayCore(char* data, const std::size_t dLen) noexcept;
            static std::optional<std::string> SCryptHashCore(const char* password,
            std::size_t pLen, const char* salt, std::size_t sLen) noexcept;
        public:
            static std::string Base64UrlEndoce(std::string_view data);
            static std::string Base64UrlDecodeWithCheck(std::string_view input);
            static std::optional<std::vector<char>> GenerateRandomVector(std::size_t size) noexcept;
            static std::optional<std::string> GenerateRandomString(std::size_t size) noexcept;
            template <std::size_t N>
            static std::optional<std::array<char, N>>  GenerateRandomArray() noexcept{
                std::array<char, N> result;
                bool opResult = CryptMaster::TryGenRandomArrayCore(result.data(), N);
                if(opResult){
                    return result;
                }
                else{
                    return {};
                }
            }
            static bool GenerateRsaKey(std::string & out_pub_key, std::string & out_pri_key) noexcept;
            static std::optional<std::string> SCryptHash(const std::string& password, const std::string& salt) noexcept;
            template <std::size_t N>
            static std::optional<std::string> SCryptHash(const std::string& password, const std::array<char, N>& salt) noexcept{
                return CryptMaster::SCryptHashCore(password.c_str(), password.size(),
                salt.data(), N);
            }
    };
}
