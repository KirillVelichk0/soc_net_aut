#include "pgAuth.hpp"
#include "jwt.hpp"
#include "cryptCore.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include "cryptCore.hpp"
#include "jwt.hpp"
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
        "SELECT insert_token($1, $2, $3) as res",
        uPGN::Query::Name{"tokenRegistator"},
    };
    auto transRes =
        transactionR.Execute(tokenRegistrateQuery, uid, publicKey, t_c);
    transactionR.Commit();
    return transRes.AsSingleRow<std::int64_t>();
  };
  return MyMicro::JWT_Token_Master::CreateToken(registrator, uid);
}
std::tuple<std::int64_t, std::string> PgAuthMaster::VerifyToken(
    userver::storages::postgres::ClusterPtr cluster, const std::string& jwt) {
  std::int64_t uid = -1;
  auto dataGetter = [&cluster,
                     &uid](const std::int64_t& token_id) -> std::string {
    namespace uPGN = userver::storages::postgres;
    auto transactionR = CreateTransactionRpRead(cluster);
    const uPGN::Query tokenGetterQuery{
        "SELECT uid, open_key from users_tokens_info "
        "where tid = $1",
        uPGN::Query::Name{"tokenDataGetter"},
    };
    auto transRes = transactionR.Execute(tokenGetterQuery, token_id);
    transactionR.Commit();
    if (!transRes.IsEmpty()) {
      auto row = transRes[0];  // there is single row
      uid = row["uid"].As<std::int64_t>();
      return row["open_key"].As<std::string>();
    } else {
      return "";
    }
  };
  auto resV = MyMicro::JWT_Token_Master::Verify(dataGetter, jwt);
  using state = MyMicro::JWT_Token_Master::GWTStates;
  switch (resV) {
    case state::Ok:
      return std::make_tuple(uid, jwt);
    case state::GoodOld:
      return std::make_tuple(uid,
                             PgAuthMaster::CreateTokenFromID(cluster, uid));
    case state::BadOld:
    case state::DontEq:
      return std::make_tuple(-1, "");
  }
}
std::string PgAuthMaster::TryRegistrate(
    userver::storages::postgres::ClusterPtr cluster, const std::string& email,
    const std::string& password) {
  auto salt = MyMicro::CryptMaster::GenerateRandomArray<32>();
  auto saltedPass = MyMicro::CryptMaster::SCryptHash(password, salt.value());
  auto verifP = MyMicro::CryptMaster::GenerateRandomArray<32>();
  auto arrayToStringConverter = [](const auto& arrayCont) {
    std::string result;
    std::copy(arrayCont.value().cbegin(), arrayCont.value().cend(),
              std::back_inserter(result));
    return result;
  };
  namespace uPGN = userver::storages::postgres;
  auto transactionR = CreateTransactionRpRead(cluster);
  const uPGN::Query registratorQuery{
      "SELECT from try_register($1, $2, $3, $4) as res",
      uPGN::Query::Name{"passIdGetter"},
  };
  auto saltS = arrayToStringConverter(salt);
  auto verifPS = arrayToStringConverter(verifP);
  auto transRes = transactionR.Execute(registratorQuery, email,
                                       saltedPass.value(), saltS, verifPS);
  transactionR.Commit();
  if (!transRes.IsEmpty()) {
    auto regData = std::to_string(transRes.AsSingleRow<std::int64_t>());
    regData += "."s + CryptMaster::Base64UrlEndoce(verifPS);
    return regData;

  } else {
    throw std::runtime_error("Cant registrate via error");
  }
}
// some piece of sh**
std::string execAndGetRes(const std::string& sCmd) {
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
void PgAuthMaster::SendToEmail(const std::string& where,
                               const std::string& data) {
  std::string answer;
  try {
    answer = execAndGetRes("python ../python_sources/emailSender.py "s + where +
                           " "s + data);
  } catch (std::runtime_error& er) {
    throw er;
  }
  std::istringstream isstr(answer);
  std::int32_t erCode;
  isstr >> erCode;
  if (erCode != 0) {
    throw std::runtime_error("Python script terminated with errCode "s +
                             std::to_string(erCode));
  }
}
std::string PgAuthMaster::TryRegistrateAndSend(
    userver::storages::postgres::ClusterPtr cluster, const std::string& email,
    const std::string& password) {
  try {
    auto regRes = PgAuthMaster::TryRegistrate(cluster, email, password);
    PgAuthMaster::SendToEmail(email, regRes);
  } catch (std::runtime_error& er) {
    throw er;
  }
}
std::string PgAuthMaster::AuthFromPassword(userver::storages::postgres::ClusterPtr cluster, const std::string& email, const std::string& password){
    namespace uPGN = userver::storages::postgres;
    auto transactionR = CreateTransactionRpRead(cluster);
    const uPGN::Query authDataGetterQuery{
        "SELECT uid, pass_h, salt from users_main_table WHERE email == $1",
        uPGN::Query::Name{"authQ"},
    };
    auto transRes = transactionR.Execute(authDataGetterQuery, email);
    transactionR.Commit();
    if(!transRes.IsEmpty()){
      auto row = transRes[0];
      auto uid= row["uid"].As<std::int64_t>();
      auto pass_h = row["pass_h"].As<std::string>();
      auto salt = row["salt"].As<std::string>();
      auto pass_h_calced = CryptMaster::SCryptHash(password, salt);
      if(pass_h_calced.has_value()){
        if(pass_h_calced.value() == pass_h){
          return PgAuthMaster::CreateTokenFromID(cluster, uid);
        }
        else{
          throw std::invalid_argument("Uncorrect login or password");
        }
      }
      else{
        throw std::bad_optional_access();
      }
    }
    else{
      throw std::runtime_error("There is no account with current email");
    }
}
std::string PgAuthMaster::VerifyRegistration(
    userver::storages::postgres::ClusterPtr cluster,
    const std::string_view reg_token) {
  std::int64_t u_id;
  std::string randomTokenData;
  auto it = std::find(reg_token.cbegin(), reg_token.cend(), '.');
  try {
    if (it == reg_token.cend()) {
      throw std::invalid_argument("Uncorrect token");
    }
    auto to_view_my = [](std::string_view::const_iterator first, std::string_view::const_iterator last) -> std::string_view{
      return first != last ? std::string_view{ first, last - first } : std::string_view{ nullptr, 0 };
    };
    randomTokenData = CryptMaster::Base64UrlDecodeWithCheck(
        to_view_my(it, reg_token.cend()));
    namespace uPGN = userver::storages::postgres;
    auto transactionR = CreateTransactionRpRead(cluster);
    const uPGN::Query verifingQuery{
        "SELECT * from try_verify($1, $2)",
        uPGN::Query::Name{"verifyQ"},
    };
    auto transRes = transactionR.Execute(verifingQuery, u_id, randomTokenData);
    transactionR.Commit();
    if (!transRes.IsEmpty()) { 
      //single row
      return transRes.AsSingleRow<std::string>();
    }
    else{
      throw std::invalid_argument("Uncorrect registration data");
    } //такой ситуации не будет
  } catch (std::exception& e) {
    return e.what();
    throw e;
  }
}
}  // namespace MyMicro
