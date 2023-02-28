#include "jwt.hpp"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sstream>
#include <algorithm>
#include <userver/crypto/exception.hpp>
using namespace std::string_literals;
namespace MyMicro {
std::tuple<std::string, std::string, std::string> JWT_Token_Master::GetElems(
    std::string_view jwt) {
  try {
    std::string strElems[3];
    auto curIt = jwt.cbegin();
    auto endIt = jwt.cend();
    for(std::size_t i = 0; i < 2; i++){
      auto nextIt = std::find(curIt, endIt, '.');
      if(nextIt != endIt){
        strElems[i] = std::string(curIt, nextIt);
        curIt = std::next(nextIt, 1);
      }
      else{
        throw std::invalid_argument("Uncorrect jwt string input");
      }
    }
    strElems[2] = std::string(curIt, endIt);
    auto sHeader = CryptMaster::Base64UrlDecodeWithCheck(strElems[0]);
    auto sPayload = CryptMaster::Base64UrlDecodeWithCheck(strElems[1]);
    auto sSign = CryptMaster::Base64UrlDecodeWithCheck(strElems[2]);
    return std::make_tuple(sHeader, sPayload, sSign);
  } catch(std::invalid_argument& _){
    throw _;
  } catch(std::exception& _){
    throw _;
  }
}

}  // namespace MyMicro
