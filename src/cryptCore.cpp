#include "cryptCore.hpp"
#include <libscrypt.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
namespace MyMicro {
bool CryptMaster::GenerateRsaKey(std::string& out_pub_key,
                                 std::string& out_pri_key) noexcept {
  size_t pri_len = 0;       // Private key length
  size_t pub_len = 0;       // public key length
  char* pri_key = nullptr;  // private key
  char* pub_key = nullptr;  // public key

  // Generate key pair
  RSA* keypair = RSA_generate_key(2048, RSA_3, NULL, NULL);
  BIO* pri = BIO_new(BIO_s_mem());
  BIO* pub = BIO_new(BIO_s_mem());
  if (pri == NULL || pub == NULL || keypair == NULL) {
    return false;
  }
  // Generate private key
  int writeRes =
      PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
  // Note------Generate the public key in the first format
  // PEM_write_bio_RSAPublicKey(pub, keypair);
  //  Note------Generate the public key in the second format (this is used in
  //  the code here)
  writeRes *= PEM_write_bio_RSA_PUBKEY(pub, keypair);
  if (writeRes == 0) {
    return false;
  }
  // Get the length
  pri_len = BIO_pending(pri);
  pub_len = BIO_pending(pub);

  // The key pair reads the string
  pri_key = (char*)malloc(pri_len + 1);
  pub_key = (char*)malloc(pub_len + 1);
  int readRes1;
  int readRes2;
  readRes1 = BIO_read(pri, pri_key, pri_len);
  readRes2 = BIO_read(pub, pub_key, pub_len);
  if (readRes1 < 1 || readRes2 < 1) {
    return false;
  }
  pri_key[pri_len] = '\0';
  pub_key[pub_len] = '\0';

  out_pub_key = pub_key;
  out_pri_key = pri_key;

  // release memory
  RSA_free(keypair);
  BIO_free_all(pub);
  BIO_free_all(pri);

  free(pri_key);
  free(pub_key);
  return true;
}
bool CryptMaster::TryGenRandomArrayCore(char* data,
                                        const std::size_t dLen) noexcept {
  auto opResult = RAND_priv_bytes(reinterpret_cast<unsigned char*>(data), dLen);
  return (opResult == 1);
}
std::optional<std::string> CryptMaster::SCryptHashCore(
    const char* password, std::size_t pLen, const char* salt,
    std::size_t sLen) noexcept {
  constexpr std::size_t bufLen = 32;
  char buf[bufLen];
  std::optional<std::string> result;

  auto op_result =
      libscrypt_scrypt(reinterpret_cast<const uint8_t*>(password), pLen,
                       reinterpret_cast<const uint8_t*>(salt), sLen, 16384, 8, 1,
                       reinterpret_cast<uint8_t*>(buf), bufLen);
  if (op_result == 0) {
    result = std::string(buf, bufLen);
  }
  return result;
}
std::optional<std::string> CryptMaster::SCryptHash(
    const std::string& password, const std::string& salt) noexcept {
  return CryptMaster::SCryptHashCore(password.c_str(), password.size(),
                                     salt.c_str(), salt.size());
}
  // namespace MyMicro
std::optional<std::vector<char>> CryptMaster::GenerateRandomVector(std::size_t size) noexcept {
  std::vector<char> result(size);
  bool opResult = CryptMaster::TryGenRandomArrayCore(
      result.data(), size);
  if (opResult) {
    return result;
  } else {
    return {};
  }
}
std::optional<std::string> CryptMaster::GenerateRandomString(
    std::size_t size) noexcept {
  std::string result(size, '0');
  bool opResult = CryptMaster::TryGenRandomArrayCore(
      result.data(), size);
  if (opResult) {
    return result;
  } else {
    return {};
  }
}
}