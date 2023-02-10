#include "jwt.hpp"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sstream>
#include <userver/crypto/exception.hpp>
using namespace std::string_literals;
namespace MyMicro {
std::tuple<std::string, std::string, std::string> JWT_Token_Master::GetElems(
    const std::string& jwt) {
  try {
    std::stringstream sstr(jwt);
    std::string sHeader;
    std::string sPayload;
    std::string sSign;
    std::getline(sstr, sHeader, '.');
    std::getline(sstr, sPayload, '.');
    sstr >> sSign;
    sHeader = userver::crypto::base64::Base64UrlDecode(sHeader);
    sPayload = userver::crypto::base64::Base64UrlDecode(sPayload);
    sSign = userver::crypto::base64::Base64UrlDecode(sSign);
    return std::make_tuple(sHeader, sPayload, sSign);
  } catch (userver::crypto::CryptoException& ex) {
    throw userver::crypto::CryptoException(ex.what());
  }
}

}  // namespace MyMicro
