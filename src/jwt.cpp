#include "jwt.hpp"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sstream>
#include <algorithm>
#include <userver/crypto/exception.hpp>
using namespace std::string_literals;
namespace MyMicro {
std::string Base64UrlDecodeWithCheck(std::string_view input){
  auto CorrectSymbol = [](auto symb){
    return (symb >= 'A' && symb <= 'Z') || (symb >= 'a' && symb <= 'z') || (symb >= '0' && symb <= '9')
    || (symb == '_') || (symb == '-');
  };
  if(input.size() > 1000){
    throw std::invalid_argument("Uncorrect Base64Url size");
  }
  auto it = std::find_if_not(input.cbegin(), input.cend(), CorrectSymbol);
  if(it == input.cend() || *it == '='){
    return userver::crypto::base64::Base64UrlDecode(input);
  }
  else{
    throw std::invalid_argument("Uncorrect symbols at "s + std::string(input));
  }
}
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
    auto sHeader = Base64UrlDecodeWithCheck(strElems[0]);
    auto sPayload = Base64UrlDecodeWithCheck(strElems[1]);
    auto sSign = Base64UrlDecodeWithCheck(strElems[2]);
    return std::make_tuple(sHeader, sPayload, sSign);
  } catch(std::invalid_argument& _){
    throw _;
  } catch(std::exception& _){
    throw _;
  }
}

}  // namespace MyMicro
