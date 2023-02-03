#pragma once
#include <chrono>
#include <string>
#include <tuple>
#include <userver/crypto/crypto.hpp>
#include <userver/formats/json.hpp>
using namespace std::string_literals;
namespace MyMicro {
using JInt = std::string;
class JWT_Token_Master{
private:
    static constexpr std::int16_t GoodHoursCount = 720;
    static constexpr std::int64_t LimForNewGenInSeconds = 360 * 3600;
    static_assert(JWT_Token_Master::GoodHoursCount * 60 * 60 >= JWT_Token_Master::LimForNewGenInSeconds);
public:

    enum class GWTStates {Ok, DontEq, BadOld, GoodOld};
    static void GenerateRsaKey(std::string & out_pub_key, std::string & out_pri_key);
    //Callable принимает триплет (int64 user id, string openKey, int64 unixT), регистрирует 
    //открытые данные в бд
    //и возвращает id токена в базе данных
    //токен однозначно идентифицирует владельца, содержа данные о нем и его цифровую подпись
    template <class Callable>
    static std::string CreateToken(Callable&& registrator, std::uint64_t userId){
    std::string priv;
    JInt outPublicKey;
    std::int64_t t_c = std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + std::chrono::hours(720)).time_since_epoch()).count();
    JWT_Token_Master::GenerateRsaKey(outPublicKey, priv);
    std::int64_t tokenId = registrator(userId, outPublicKey, t_c);
    auto signer = userver::crypto::SignerRs256(priv);
    userver::formats::json::ValueBuilder builderH;
    builderH["alg"] = "RS256";
    builderH["type"] = "JWT";
    auto jsonHeader = builderH.ExtractValue();
    userver::formats::json::ValueBuilder builderP;
    builderP["tokenId"] = tokenId;
    builderP["sub"] = "authToken";
    builderP["exp"] = t_c;
    auto jsonPayload = builderP.ExtractValue();
    auto sh = userver::crypto::base64::Base64UrlEncode(userver::formats::json::ToString(jsonHeader));
    auto sp = userver::crypto::base64::Base64UrlEncode(userver::formats::json::ToString(jsonPayload));
    auto signature = userver::crypto::base64::Base64UrlEncode(signer.Sign({sh, sp}));
    return sh + "."s + sp + "."s + signature;
}
    static std::tuple<std::string, std::string, std::string> GetElems(const std::string& jwt);
    //в моем проекте предполагается использование только Rs256, поэтому поле алгоритма даже не осматривается
    //Callable принимает id токена и возвращает открытый ключ. Если он пуст, значит такого токена нет
    template <class Callable>
    static GWTStates Verify(Callable&& openKeyGetter, const std::string& jwt){
    auto parsedJWT = JWT_Token_Master::GetElems(jwt);    
    std::string sHeader = std::get<0>(parsedJWT);
    std::string sPayload = std::get<1>(parsedJWT);
    std::string sSign = std::get<2>(parsedJWT);
    
    auto jPayload = userver::formats::json::FromString(sPayload);
    auto tokenId = jPayload["tokenId"s].As<std::int64_t>();
    JInt openKey = openKeyGetter(tokenId);
    if(openKey == ""){
        return JWT_Token_Master::GWTStates::BadOld;
    }
    auto verifier = userver::crypto::VerifierRs256(openKey);
    
    try{
        using userver::crypto::base64::Base64UrlEncode;
        auto encodedH = Base64UrlEncode(sHeader);
        auto encodedP = Base64UrlEncode(sPayload);
        verifier.Verify({encodedH, encodedP}, sSign);
        
        if(jPayload["sub"s].As<std::string>() != "authToken"){
            //throw userver::crypto::VerificationError();
        }
        std::int64_t tokenDate = jPayload["exp"s].As<std::int64_t>();
        std::int64_t c_p = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if(c_p > tokenDate){
            return JWT_Token_Master::GWTStates::BadOld;
        }
        else if(c_p > tokenDate - 360 * 3600){ //someMagicDates
            return JWT_Token_Master::GWTStates::GoodOld;
        }
        return JWT_Token_Master::GWTStates::Ok;
    } catch(userver::crypto::VerificationError& _){
        return JWT_Token_Master::GWTStates::DontEq;
    }
}
};
}
