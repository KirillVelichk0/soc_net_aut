#include "AuthGRPC.hpp"
#include "pgAuth.hpp"

void AuthGrpcComponent::Authenticate(AuthenticateCall& call,
                                     AuthInput&& request) {
  AuthResult grpc_response;
  auto [userId, jwt] =
      MyMicro::PgAuthMaster::VerifyToken(this->pg_cluster_, request.jwttoken());
  grpc_response.set_userid(userId);
  grpc_response.set_nexttoken(jwt);
  call.Finish(grpc_response);
}
void AuthGrpcComponent::TryRegistr(TryRegistrCall& call, RegistrationInput&& request) {
    RegistrationResult grpc_response;
    try{
        auto regRes = MyMicro::PgAuthMaster::TryRegistrateAndSend(this->pg_cluster_, request.email(), request.password());
        grpc_response.set_isok(true);
        grpc_response.set_answer(regRes);
    } catch(std::runtime_error& _){
        grpc_response.set_isok(false);
        grpc_response.set_answer("");
    }
    call.Finish(grpc_response);
}
void AuthGrpcComponent::TryVerifRegistr(
    TryVerifRegistrCall& call, RegistrationVerificationInput&& request) {
        RegistrationVerificationResult grpc_response;
        try{
            auto res = MyMicro::PgAuthMaster::VerifyRegistration(this->pg_cluster_, request.randomdatatoken());
            grpc_response.set_isok(true);
            grpc_response.set_token(res);
        } catch (std::exception& e){
            grpc_response.set_isok(false);
            grpc_response.set_token(e.what());
        }
        call.Finish(grpc_response);
    }