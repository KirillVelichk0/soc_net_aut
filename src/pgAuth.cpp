#include "pgAuth.hpp"
#include "jwt.hpp"
#include <array>
#include <stdexcept>
#include "cryptCore.hpp"
#include <cstdlib>
#include <sstream>
#include <cstdint>
#include <algoritm>
#include <memory>
#include <optional>
#include <cstdio>
#include <iostream>
using namespace std::string_literals;
namespace MyMicro {
auto CreateTransactionRpRead(userver::storages::postgres::ClusterPtr& cluster) {
  namespace uPGN = userver::storages::postgres;
  constexpr auto isolationLevel = uPGN::IsolationLevel::kRepeatableRead;
  uPGN::TransactionOptions trO{isolationLevel};
  return cluster->Begin(trO);
}
std::string PgAuthMaster::CreateTokenFromID(
    userver::storages::postgres::ClusterPtr cluster, const std::int64_t& uid) {
  auto registrator = [&cluster](const std::int64_t& uid,
                                const std::string& publicKey,
                                const std::int64_t& t_c) {
    namespace uPGN = userver::storages::postgres;
    auto transactionR = CreateTransactionRpRead(cluster);
    const uPGN::Query tokenRegistrateQuery{
        "SELECT * from insert_token($1, $2, $3) ",
        uPGN::Query::Name{"tokenRegistator"},
    };
    auto transRes =
        transactionR.execute(tokenRegistrateQuery, uid, publicKey, t_c);
    transactionR.Commit();
    return transRes.AsSingleRow<std::int64_t>();
  };
  return MyMicro::JWT_Token_Master::CreateToken(regitsrator, uid);
}
std::tuple<std::int64_t, std::string> PgAuthMaster::VerifyToken(
    userver::storages::postgres::ClusterPtr cluster, const std::string& jwt) {
  std::int64_t uid = -1;
  auto dataGetter = [&cluster, &uid](const std::int64_t& token_id) {
    namespace uPGN = userver::storages::postgres;
    auto transactionR = CreateTransactionRpRead(cluster);
    const uPGN::Query tokenGetterQuery{
        "SELECT uid, open_key from users_tokens_info "
        "where tid = $1",
        uPGN::Query::Name{"tokenDataGetter"},
    };
    auto transRes = transactionR.execute(tokenGetterQuery, token_id);
    transactionR.Commit();
    if (!transRes.IsEmpty()) {
      auto row = transRes[0];  // there is single row
      uid = row["uid"].As<std::int64_t>();
      return row["open_key"].As<std::string>();
    }
    else{
        return "";
    }
  };
  auto resV = MyMicro::JWT_Token_Master::Verify(dataGetter, jwt);
  using state = MyMicro::JWT_Token_Master::GWTStates;
  switch (resV){
    case state::Ok:
        return std::make_tuple(uid, jwt);
    case state::GoodOld:
        return std::make_tuple(uid, PgAuthMaster::CreateTokenFromID(cluster, uid));
    case state::BadOld:
    case state::DontEq:
        return std::make_tuple(-1, "");

  }
}
std::string PgAuthMaster::TryRegistrate(userver::storages::postgres::ClusterPtr cluster, const std::string& email, const std::string& password){
    auto salt = MyMicro::CryptMaster::GenerateRandomArray<32>();
    auto saltedPass = MyMicro::CryptMaster::SCryptHash(password, salt);
    auto verifP = MyMicro::CryptMaster::GenerateRandomArray<32>();
    auto arrayToStringConverter = [](const auto& arrayCont){
        std::string result;
        std::copy(arrayCont.cbegin(), arrayCont.cend(), std::back_inserter(result));
        return result;
    };
    namespace uPGN = userver::storages::postgres;
    auto transactionR = CreateTransactionRpRead(cluster);
    const uPGN::Query registratorQuery{
        "SELECT * from try_register($1, $2, $3, $4)",
        uPGN::Query::Name{"passIdGetter"},
    };
    auto saltS = arrayToStringConverter(salt); 
    auto verifPS = arrayToStringConverter(verifP);
    auto transRes = transactionR.execute(registratorQuery, email, saltedPass.value(), saltS, verifPS);
    transactionR.Commit();
    if (!transRes.IsEmpty()) {
      auto row = transRes[0];  // there is single row
      auto regData = std::to_string(row["uid"].As<std::int64_t>());
      regData += "."s + CryptMaster::Base64UrlEndoce(verifPS);
      return regData;

    }
    else{
        throw std::runtime_error("Cant registrate via error");
    }
}
//some piece of sh**
std::string execAndGetRes(const std::string &sCmd) {
    const char* cmd = sCmd.c_str();
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}
void PgAuthMaster::SendToEmail(const std::string& where, const std::string& data){
  std::string answer;
  try{
    answer = execAndGetRes("python ../python_sources/emailSender.py "s + where + " "s + data);
  } catch (std::runtime_error& er){
    throw er;
  }
  std::istringstream isstr(answer);
  std::int32_t erCode;
  isstr >> erCode;
  if(erCode != 0){
    throw std::runtime_error("Python script terminated with errCode "s + std::to_string(erCode));
  }
}
std::string PgAuthMaster::TryRegistrateAndSend(userver::storages::postgres::ClusterPtr cluster, const std::string& email, const std::string& password){
  try{
    auto regRes = PgAuthMaster::TryRegistrate(cluster, email, password);

  } catch (std::runtime_error& er){
    throw er;
  }
}
}  // namespace MyMicro
