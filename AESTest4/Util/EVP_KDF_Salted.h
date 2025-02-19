//
//  EVP_KDF_Salted.h
//  AESTest4
//
//  Created by Way on 09/05/2024.
//

#include <openssl/evp.h>
#include <string.h>

int
gen_evp_kdf_aes256cbc1(const unsigned char *password, const unsigned char *salt, unsigned char key[], unsigned char iv[]) {
    
    const EVP_CIPHER *cipher;
    const EVP_MD *dgst = NULL;
    
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CONFIG, NULL);
    
    cipher = EVP_get_cipherbyname("aes-256-cbc");
    if(!cipher) { fprintf(stderr, "no such cipher\n"); return 1; }
    
    dgst=EVP_get_digestbyname("md5");
    if(!dgst) { fprintf(stderr, "no such digest\n"); return 1; }
    
    int result = EVP_BytesToKey(cipher, dgst, salt, password, strlen(password), 1, key, iv);
    
    if (!result) {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }
    return 0;
}
