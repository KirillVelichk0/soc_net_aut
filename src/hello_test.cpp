#include "hello.hpp"
#include "jwt.hpp"
#include "cryptCore.hpp"
#include <userver/utest/utest.hpp>
#include <userver/formats/json.hpp>
#include <userver/crypto/crypto.hpp>
#include <openssl/rsa.h>
#include <string>
#include <chrono>
#include <tuple>
#include <openssl/pem.h>
using namespace std::string_literals;
UTEST(CryptCoreTests, RSATest){
  std::string open; std::string close;
  using MyMicro::JWT_Token_Master;
  MyMicro::CryptMaster::GenerateRsaKey(open, close);
  auto signer = userver::crypto::SignerRs256(close);
  auto verifier = userver::crypto::VerifierRs256(open);
  std::string message = "AraAra122222222222222222222222222222adfdsfasdfsadfasdfasdfasdfsdafsdfsdfewqrewrwetretwljfsahgiorejgfjkshigerghioajgkjsahgoireghkjsashogfihwejkhaosidngjkheuirgnlahfguhisad";
  std::string signature = signer.Sign({message});
  bool verRes = true;
  try{
    verifier.Verify({message}, signature);
  } catch(userver::crypto::VerificationError& _){
    verRes = false;
  }
  EXPECT_TRUE(verRes);
  std::string message2 = "OraOra125e67tsydiufg7632yiurfydsafih6tt32y78hugduishf78t326gfuday77823y783gt67aaaaaaaaaaaaaaaaaaaaaasdfdsa";
  std::string signature2 = signer.Sign({message, message2});
  bool verRes2 = true;
  try{
    verifier.Verify({message, message2}, signature2);
  } catch(userver::crypto::VerificationError& _){
    verRes2 = false;
  }
  EXPECT_TRUE(verRes2);
}
UTEST(JWTTests, GetterTest){
  using MyMicro::JWT_Token_Master;
  using userver::crypto::base64::Base64UrlEncode;
  std::string x1 = "Cringe"; std::string x2 = "!#@%&"; std::string x3 = "12345";
  std::string y1 = Base64UrlEncode(x1); std::string y2 = Base64UrlEncode(x2); 
  std::string y3 = Base64UrlEncode(x3);
  std::string sign = y1 + "."s + y2 + "."s + y3;
  auto res = JWT_Token_Master::GetElems(sign);
  auto z1 = x1; auto z2 = x2; auto z3 = x3;
  EXPECT_EQ(z1, std::get<0>(res));
  EXPECT_EQ(z2, std::get<1>(res));
  EXPECT_EQ(z3, std::get<2>(res));
}
UTEST(JWTTests, Basic) {
  using soc_net_aut::SayHelloTo;
  using soc_net_aut::UserType;
  using MyMicro::JWT_Token_Master;
  std::string openKeyC;
  auto registrator = [&openKeyC](std::int64_t id, std::string& openKey, std::int64_t t_c) mutable -> std::int64_t{
    openKeyC = openKey;
    return 1;
  };
  auto keyGetter = [&openKeyC](auto id) mutable {
    return openKeyC;
  };
  auto token = JWT_Token_Master::CreateToken(registrator, 1);
  EXPECT_TRUE(keyGetter(1).size() > 0);
  EXPECT_TRUE(openKeyC.size() > 0);
  EXPECT_TRUE(token.size() > 0);
  auto result = JWT_Token_Master::Verify(keyGetter, token);
  EXPECT_EQ(JWT_Token_Master::GWTStates::Ok, result);
  
}
