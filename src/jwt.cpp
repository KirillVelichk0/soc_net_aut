#include "jwt.hpp"
#include <sstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
using namespace std::string_literals;
namespace  MyMicro {
void JWT_Token_Master::GenerateRsaKey(std::string & out_pub_key, std::string & out_pri_key){
    size_t pri_len = 0; // Private key length
        size_t pub_len = 0; // public key length
         char *pri_key = nullptr; // private key
         char *pub_key = nullptr; // public key

         // Generate key pair
        RSA *keypair = RSA_generate_key(2048, RSA_3, NULL, NULL);

        BIO *pri = BIO_new(BIO_s_mem());
        BIO *pub = BIO_new(BIO_s_mem());
        
             // Generate private key
        PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
             // Note------Generate the public key in the first format
        //PEM_write_bio_RSAPublicKey(pub, keypair);
             // Note------Generate the public key in the second format (this is used in the code here)
        PEM_write_bio_RSA_PUBKEY(pub, keypair);

         // Get the length
        pri_len = BIO_pending(pri);
        pub_len = BIO_pending(pub);

         // The key pair reads the string
        pri_key = (char *)malloc(pri_len + 1);
        pub_key = (char *)malloc(pub_len + 1);

        BIO_read(pri, pri_key, pri_len);
        BIO_read(pub, pub_key, pub_len);

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
}
std::tuple<std::string, std::string, std::string> JWT_Token_Master::GetElems(const std::string& jwt){
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
}

}
