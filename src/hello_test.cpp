#include "hello.hpp"
#include "jwt.hpp"
#include <random>
#include <openssl/rand.h>
#include "cryptCore.hpp"
#include <userver/utest/utest.hpp>
#include <userver/formats/json.hpp>
#include <userver/crypto/crypto.hpp>
#include <openssl/rsa.h>
#include <string>
#include <chrono>
#include <tuple>
#include <exception>
#include <stdexcept>
#include <openssl/pem.h>
#include <array>
using namespace std::string_literals;
UTEST(CryptCoreTest, SCryptTest){
  using MyMicro::CryptMaster;
  std::string password = "qwert1234567890";
  std::string salt = "qasd1e4hjlkQQ!@#juifdsjbnnvjqwerdaf";
  auto result = CryptMaster::SCryptHash(password, salt);
  bool isOk = result.has_value();
  EXPECT_TRUE(isOk);
  std::array<char, 5> saltAr = {'H', 'E', 'L', 'L', 'O'};
  result = CryptMaster::SCryptHash(password, saltAr);
  isOk = result.has_value();
  EXPECT_TRUE(isOk);
}
UTEST(CryptCoreTest, RandBytesGeneratingTest){
  using MyMicro::CryptMaster;
  for(std::size_t i = 0; i < 100; i++){
    auto arrayB = CryptMaster::GenerateRandomArray<32>();
    bool isOk = arrayB.has_value();
    EXPECT_TRUE(isOk);
    auto vectorB = CryptMaster::GenerateRandomVector(32);
    isOk = vectorB.has_value();
    EXPECT_TRUE(isOk);
    auto stringB = CryptMaster::GenerateRandomString(32);
    isOk = stringB.has_value();
    EXPECT_TRUE(isOk);
  }
}
/*UTEST(CryptCoreTest, SCryptFuzzTest){
  using MyMicro::CryptMaster;
  for(std::size_t i = 0; i < 1000; i++){
    std::string password(32, '0'); std::string salt(32, '0');
    RAND_bytes(reinterpret_cast<unsigned char*>(password.data()), 32);
    RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), 32);
    EXPECT_TRUE(CryptMaster::SCryptHash(password, salt).has_value());
  }
}*/
UTEST(CryptCore_UserverCrypt_Integr_Tests, RSA_Sign_Ver_Test){
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
  using userver::crypto::base64::Base64UrlDecode;
  std::string x1 = "Cringe"; std::string x2 = "!#@%&"; std::string x3 = "12345";
  std::string y1 = Base64UrlEncode(x1); std::string y2 = Base64UrlEncode(x2); 
  std::string y3 = Base64UrlEncode(x3);
  std::string sign = y1 + "."s + y2 + "."s + y3;
  auto res = JWT_Token_Master::GetElems(sign);
  auto z1 = x1; auto z2 = x2; auto z3 = x3;
  EXPECT_EQ(z1, std::get<0>(res));
  EXPECT_EQ(z2, std::get<1>(res));
  EXPECT_EQ(z3, std::get<2>(res));
  UEXPECT_THROW(JWT_Token_Master::GetElems("adsa.dff.f.f"s), std::invalid_argument);
  UEXPECT_THROW_MSG(JWT_Token_Master::GetElems("adsa.dffff"s), std::invalid_argument, "Uncorrect jwt string input");
  UEXPECT_THROW_MSG(JWT_Token_Master::GetElems("adsadffff"s), std::invalid_argument, "Uncorrect jwt string input");

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
  UEXPECT_THROW(userver::formats::json::FromString("arwqedfasd134"s), std::exception); // нет в доках!!!
  auto result = JWT_Token_Master::Verify(keyGetter, token);
  EXPECT_EQ(JWT_Token_Master::GWTStates::Ok, result);
  std::string val = "sdfasdfsda.asqerdasf.1324qewrf";
  EXPECT_EQ(JWT_Token_Master::Verify(keyGetter, val), JWT_Token_Master::GWTStates::DontEq);
  openKeyC[0] = openKeyC[0] + 1;
  result = JWT_Token_Master::Verify(keyGetter, token);
  EXPECT_EQ(JWT_Token_Master::GWTStates::DontEq, result);
  
}
