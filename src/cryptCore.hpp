#include <array>
#include <cwchar>
#include <openssl/rand.h>
#include <string>
namespace MyMicro{
    class CryptMaster{
        public:
            template <std::size_t N>
            static auto GenerateRandomArray() noexcept{
                std::array<char, N> result;
                RAND_priv_bytes(result.data(), N);
                return result;
            }
            static void GenerateRsaKey(std::string & out_pub_key, std::string & out_pri_key) noexcept;
    };
}