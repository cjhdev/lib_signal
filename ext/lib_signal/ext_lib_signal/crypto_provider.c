#include <ruby.h>
#include "signal_protocol.h"

int random_func(uint8_t *data, size_t len, void *user_data)
{
    VALUE bytes = rb_funcall(rb_eval_string("OpenSSL::Random"), rb_intern("random_bytes"), 1, SIZET2NUM(len));
    (void)memcpy(data, RSTRING_PTR(bytes), len);
    return 0U;
}

int hmac_sha256_init_func(void **context, const uint8_t *key, size_t key_len, void *user_data)
{
    
    VALUE ctx = rb_funcall(rb_eval_string("OpenSSL::HMAC"), rb_intern("new"), 2, rb_str_new((char *)key, key_len), rb_funcall(rb_eval_string("OpenSSL::Digest::SHA256"), rb_intern("new"), 0)); 
    
    (void)rb_ary_push(rb_iv_get((VALUE)user_data, "@refs"), ctx); 
    
    *context = (void *)ctx;
    
    return 0U;
}

int sha512_digest_init_func(void **context, void *user_data)
{
    VALUE ctx = rb_funcall(rb_eval_string("OpenSSL::Digest::SHA512"), rb_intern("new"), 0); 
    
    (void)rb_ary_push(rb_iv_get((VALUE)user_data, "@refs"), ctx); 
    
    *context = (void *)ctx;
    
    return 0U;
}

int digest_update_func(void *context, const uint8_t *data, size_t data_len, void *user_data)
{    
    (void)rb_funcall((VALUE)context, rb_intern("update"), 1, rb_str_new((char *)data, data_len));    
    return 0;
}

int digest_final_func(void *context, signal_buffer **output, void *user_data)
{
    *output = rstring_to_buffer(rb_funcall((VALUE)context, rb_intern("digest"), 0));
    return 0;
}

void digest_cleanup_func(void *context, void *user_data)
{    
    rb_funcall(rb_iv_get((VALUE)user_data, "@refs"), rb_intern("delete"), 1, (VALUE)context);
}

static VALUE init_cipher(
    int cipher,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len)
{
    VALUE retval = Qnil;
    VALUE klass;
    
    if((key_len == 16UL) || (key_len == 24UL) || (key_len == 32UL)){
        
        if((cipher == SG_CIPHER_AES_CBC_PKCS5) || (cipher == SG_CIPHER_AES_CTR_NOPADDING)){
        
            switch(key_len){
            default:
            case 16UL:
                klass = rb_eval_string("OpenSSL::Cipher::AES128");
                break;
            case 24UL:
                klass = rb_eval_string("OpenSSL::Cipher::AES196");
                break;
            case 32UL:
                klass = rb_eval_string("OpenSSL::Cipher::AES256");
                break;
            }
            
            switch(cipher){
            default:
            case SG_CIPHER_AES_CTR_NOPADDING:            
                
                retval = rb_funcall(klass, rb_intern("new"), 1, ID2SYM(rb_intern("CTR")));
                rb_funcall(retval, rb_intern("padding"), 1, UINT2NUM(0));
                break;
            
            case SG_CIPHER_AES_CBC_PKCS5:
                
                cipher = rb_funcall(retval, rb_intern("new"), 1, ID2SYM(rb_intern("CBC")));
                break;
            }
    
            (void)rb_funcall(retval, rb_intern("key"), 1, rb_str_new((char *)key, key_len));
            (void)rb_funcall(retval, rb_intern("iv"), 1, rb_str_new((char *)iv, iv_len));
            
            (void)rb_funcall(retval, rb_intern("encrypt"), 0);
        }    
    }
     
    return retval;
}

int encrypt_func(signal_buffer **output,
    int cipher,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *plaintext, size_t plaintext_len,
    void *user_data)
{
    VALUE c = Qnil;
    VALUE input;
    int retval = -1;
    
    c = init_cipher(cipher, key, key_len, iv, iv_len);
    
    if(c != Qnil){
    
        (void)rb_funcall(c, rb_intern("encrypt"), 0);
            
        input = rb_funcall(c, rb_intern("update"), 1, rb_str_new((char *)plaintext, plaintext_len));
        input = rb_funcall(input, rb_intern("append"), rb_funcall(c, rb_intern("final"), 0));
        
        *output = rstring_to_buffer(input);
        
        retval = (*output != NULL) ? 0 : -1;
    }
     
    return retval;
}

int decrypt_func(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len,
        void *user_data)
{
    VALUE c = Qnil;
    VALUE input;
    int retval = -1;
    
    c = init_cipher(cipher, key, key_len, iv, iv_len);
    
    if(c != Qnil){
    
        (void)rb_funcall(c, rb_intern("decrypt"), 0);
            
        input = rb_funcall(c, rb_intern("update"), 1, rb_str_new((char *)ciphertext, ciphertext_len));
        input = rb_funcall(input, rb_intern("append"), rb_funcall(c, rb_intern("final"), 0));
    
        *output = rstring_to_buffer(input);
            
        retval = (*output != NULL) ? 0 : -1;
    }
     
    return retval;
}
