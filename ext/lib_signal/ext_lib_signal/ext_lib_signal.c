#include "signal_protocol.h"
#include "key_helper.h"
#include "session_pre_key.h"
#include "session_builder.h"
#include "session_cipher.h"

#include <ruby.h>
#include <assert.h>
#include <stdbool.h>

struct ext_client {
    
    signal_context *ctx;
    signal_protocol_store_context *store_ctx;
};

static uint64_t my_get_time(void);
static VALUE buffer_to_rstring(const signal_buffer *buffer);
static signal_buffer *rstring_to_buffer(VALUE str);
static ec_public_key *rstring_to_ec_public_key(signal_context *ctx, VALUE str);
static ec_private_key *rstring_to_ec_private_key(signal_context *ctx, VALUE str);
static void handle_error(int error);

static VALUE eErrUnknown;
static VALUE eErrDuplicateMessage;
static VALUE eErrInvalidKey;
static VALUE eErrInvalidKeyID;
static VALUE eErrInvalidMessage;
static VALUE eErrInvalidMAC;
static VALUE eErrInvalidVersion;
static VALUE eErrLegacyMessage;
static VALUE eErrNoSession;
static VALUE eErrStaleKeyExchange;
static VALUE eErrUntrustedIdentity;
static VALUE eErrVRFSigVerifFailed;
static VALUE eErrInvalidProtoBuf;
static VALUE eErrFPVersionMismatch;
static VALUE eErrFPIdentMismatch;

/* crypto provider ****************************************************/

static int random_func(uint8_t *data, size_t len, void *user_data)
{
    VALUE bytes = rb_funcall(rb_eval_string("OpenSSL::Random"), rb_intern("random_bytes"), 1, SIZET2NUM(len));
    (void)memcpy(data, RSTRING_PTR(bytes), len);
    return 0U;
}

static int hmac_sha256_init_func(void **context, const uint8_t *key, size_t key_len, void *user_data)
{
    
    VALUE ctx = rb_funcall(rb_eval_string("OpenSSL::HMAC"), rb_intern("new"), 2, rb_str_new((char *)key, key_len), rb_funcall(rb_eval_string("OpenSSL::Digest::SHA256"), rb_intern("new"), 0)); 
    
    (void)rb_ary_push(rb_iv_get((VALUE)user_data, "@refs"), ctx); 
    
    *context = (void *)ctx;
    
    return 0U;
}

static int sha512_digest_init_func(void **context, void *user_data)
{
    VALUE ctx = rb_funcall(rb_eval_string("OpenSSL::Digest::SHA512"), rb_intern("new"), 0); 
    
    (void)rb_ary_push(rb_iv_get((VALUE)user_data, "@refs"), ctx); 
    
    *context = (void *)ctx;
    
    return 0U;
}

static int digest_update_func(void *context, const uint8_t *data, size_t data_len, void *user_data)
{    
    (void)rb_funcall((VALUE)context, rb_intern("update"), 1, rb_str_new((char *)data, data_len));    
    return 0;
}

static int digest_final_func(void *context, signal_buffer **output, void *user_data)
{
    *output = rstring_to_buffer(rb_funcall((VALUE)context, rb_intern("digest"), 0));
    return 0;
}

static void digest_cleanup_func(void *context, void *user_data)
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

static int aes_encrypt(signal_buffer **output,
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

static int aes_decrypt(signal_buffer **output,
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

/* pre key store ******************************************************/

static int get_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data)
{
    int retval = SG_ERR_INVALID_KEY_ID;

    VALUE result = rb_funcall((VALUE)user_data, rb_intern("get_pre_key"), 1, UINT2NUM(pre_key_id));
    
    if(result != Qnil){
        
        *record = rstring_to_buffer(rb_hash_aref(result, ID2SYM(rb_intern("key"))));
        retval = SG_SUCCESS;
    }
    
    return retval;
}

static int post_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
    (void)rb_funcall((VALUE)user_data, rb_intern("post_pre_key"), 2, UINT2NUM(pre_key_id), rb_str_new((char *)record, record_len));    
    return 0;
}

static int pre_key_exists(uint32_t pre_key_id, void *user_data)
{
    return (rb_funcall((VALUE)user_data, rb_intern("pre_key_exists?"), 0) == Qtrue) ? 1 : 0;
}

static int delete_pre_key(uint32_t pre_key_id, void *user_data)
{
    (void)rb_funcall((VALUE)user_data, rb_intern("delete_pre_key"), 1, UINT2NUM(pre_key_id));    
    return 0;
}

/* signed pre key store ***********************************************/

static int get_signed_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data)
{
    int retval = SG_ERR_INVALID_KEY_ID;

    VALUE result = rb_funcall((VALUE)user_data, rb_intern("get_signed_pre_key"), 1, UINT2NUM(pre_key_id));
    
    if(result != Qnil){
        
        *record = rstring_to_buffer(rb_hash_aref(result, ID2SYM(rb_intern("key"))));
        retval = SG_SUCCESS;
    }
    
    return retval;    
}

static int post_signed_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
    (void)rb_funcall((VALUE)user_data, rb_intern("post_signed_pre_key"), 2, UINT2NUM(pre_key_id), rb_str_new((char *)record, record_len));    
    return 0;
}

static int signed_pre_key_exists(uint32_t pre_key_id, void *user_data)
{
    return (rb_funcall((VALUE)user_data, rb_intern("signed_pre_key_exists?"), 0) == Qtrue) ? 1 : 0;
}

static int delete_signed_pre_key(uint32_t pre_key_id, void *user_data)
{
    (void)rb_funcall((VALUE)user_data, rb_intern("delete_signed_pre_key"), 1, UINT2NUM(pre_key_id));    
    return 0;
}

/* locking ************************************************************/

static void global_lock(void *user_data)
{
    rb_funcall(rb_iv_get((VALUE)user_data, "@global_lock"), rb_intern("lock"), 0);
}

static void global_unlock(void *user_data)
{
    rb_funcall(rb_iv_get((VALUE)user_data, "@global_lock"), rb_intern("unlock"), 0);
}

/* logging ************************************************************/

static void global_log(int level, const char *message, size_t len, void *user_data)
{
    rb_funcall((VALUE)user_data, rb_intern("log"), 2, INT2NUM(level), rb_str_new(message, len));
}

/* sender key store ***************************************************/

static int post_sender_key(const signal_protocol_sender_key_name *sender_key_name, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data)
{
    (void)rb_funcall((VALUE)user_data, rb_intern("post_sender_key"), 
        5,
        rb_str_new((char *)sender_key_name->group_id, sender_key_name->group_id_len),
        rb_str_new((char *)sender_key_name->sender.name, sender_key_name->sender.name_len),
        INT2NUM(sender_key_name->sender.device_id),
        rb_str_new((char *)record, record_len),
        rb_str_new((char *)user_record, user_record_len)        
    );
    
    return 0;
}

static int get_sender_key(signal_buffer **record, signal_buffer **user_record, const signal_protocol_sender_key_name *sender_key_name, void *user_data)
{
    int retval = 0;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("get_sender_key"),
        3,
        rb_str_new((char *)sender_key_name->group_id, sender_key_name->group_id_len),
        rb_str_new((char *)sender_key_name->sender.name, sender_key_name->sender.name_len),
        INT2NUM(sender_key_name->sender.device_id)
    );
    
    if(result != Qnil){
        
        *record = rstring_to_buffer(rb_hash_aref(result, ID2SYM(rb_intern("record"))));
        *user_record = (rb_hash_aref(result, ID2SYM(rb_intern("user_record"))) != Qnil) ? rstring_to_buffer(rb_hash_aref(result, ID2SYM(rb_intern("user_record")))) : NULL;
        
        retval = 1;
    }
    
    return retval;
}

/* identity key store *************************************************/

static int get_identity_key_pair(signal_buffer **public_data, signal_buffer **private_data, void *user_data)
{
    int retval = -1;

    VALUE result = rb_funcall((VALUE)user_data, rb_intern("get_identity_key_pair"), 0);
    
    if(result != Qnil){
    
        *public_data = rstring_to_buffer(rb_hash_aref(result, ID2SYM(rb_intern("public"))));
        *private_data = rstring_to_buffer(rb_hash_aref(result, ID2SYM(rb_intern("private"))));
    
        retval = 0;
    }    
        
    return retval;
}

static int get_local_registration_id(void *user_data, uint32_t *registration_id)
{
    int retval = -1;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("get_registration_id"), 0);
    
    if(result != Qnil){
        
        *registration_id = NUM2UINT(result);
        
        retval = 0;
    }
    
    return retval;
}

static int post_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    (void)rb_funcall((VALUE)user_data, rb_intern("post_identity"), 
        3, 
        rb_str_new((char *)address->name, address->name_len), 
        INT2NUM(address->device_id),
        rb_str_new((char *)key_data, key_len)
    );
    
    return 0;
}

static int identity_is_trusted(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("identity_is_trusted?"), 
        3,
        rb_str_new((char *)address->name, address->name_len), 
        INT2NUM(address->device_id),
        rb_str_new((char *)key_data, key_len)        
    );
    
    return (result == Qtrue) ? 1 : 0;
}

/* session store ******************************************************/

static int get_session(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data)
{
    int retval = 0;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("get_session"), 
        1, 
        rb_str_new((char *)address->name, address->name_len), 
        INT2NUM(address->device_id)
    );
    
    if(result != Qnil){
        
        *record = rstring_to_buffer(rb_hash_aref(result, ID2SYM(rb_intern("record"))));
        *user_record = (rb_hash_aref(result, ID2SYM(rb_intern("user_record"))) != Qnil) ? rstring_to_buffer(rb_hash_aref(result, ID2SYM(rb_intern("user_record")))) : NULL;
        retval = 1;
    }
    
    return retval;
}

static int get_session_ids(signal_int_list **sessions, const char *name, size_t name_len, void *user_data)
{
    int retval = 0;
    int i;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("get_session_devices"), 1, rb_str_new((char *)name, name_len));
        
    retval = NUM2INT(rb_funcall(result, rb_intern("size"), 0));
    *sessions = signal_int_list_alloc();
    
    for(i=0U; i < retval; i++){
        
        (void)signal_int_list_push_back(*sessions, rb_ary_entry(result, i));
    }
    
    return retval;
}

static int post_session(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data)
{
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("post_session"), 
        4,
        rb_str_new((char *)address->name, address->name_len), 
        INT2NUM(address->device_id),
        rb_str_new((char *)record, record_len),
        rb_str_new((char *)user_record, user_record_len)
    );
    
    return (result == Qtrue) ? 0 : -1;
}

static int session_exists(const signal_protocol_address *address, void *user_data)
{
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("session_exists?"), 
        2, 
        rb_str_new((char *)address->name, address->name_len), 
        INT2NUM(address->device_id)
    );
    
    return (result == Qtrue) ? 0 : -1;
}

static int delete_session(const signal_protocol_address *address, void *user_data)
{
    (void)rb_funcall((VALUE)user_data, rb_intern("delete_session"), 
        2,
        rb_str_new((char *)address->name, address->name_len), 
        INT2NUM(address->device_id)        
    );
    
    return 0;
}

static int delete_all_sessions(const char *name, size_t name_len, void *user_data)
{
    (void)rb_funcall((VALUE)user_data, rb_intern("delete_all_sessions"), 
        1, 
        rb_str_new((char *)name, name_len)
    );
    
    return 0;
}

/* generic destroy function *******************************************/

static void destroy_func(void *user_data)
{
}

/* methods ************************************************************/

static VALUE initialize(VALUE self, VALUE data)
{
    struct ext_client *this;    
    Data_Get_Struct(self, struct ext_client, this);
    
    if(rb_obj_is_kind_of(data, rb_eval_string("Persistence")) != Qtrue){        
    
        rb_raise(rb_eTypeError, "data must be a Persistence subclass");
    }
    
    /* this keeps references to objects created by the extension 
     * so the GC doesn't collect them */
    rb_iv_set(self, "@refs", rb_ary_new());
    
    rb_iv_set(self, "@global_lock", rb_funcall(rb_eval_string("Monitor"), rb_intern("new"), 0));
    rb_iv_set(self, "@data", data);
    
    if(signal_context_create(&this->ctx, (void *)self) != 0){
        
        rb_bug("signal_context_create()");
    }

    const struct signal_crypto_provider crypto_provider = {
        .random_func = random_func,
        .hmac_sha256_init_func = hmac_sha256_init_func,
        .hmac_sha256_update_func = digest_update_func,
        .hmac_sha256_final_func = digest_final_func,
        .hmac_sha256_cleanup_func = digest_cleanup_func,
        .sha512_digest_init_func = sha512_digest_init_func,
        .sha512_digest_update_func = digest_update_func,
        .sha512_digest_final_func = digest_final_func,
        .sha512_digest_cleanup_func = digest_cleanup_func,
        .encrypt_func = aes_encrypt,
        .decrypt_func = aes_decrypt,
        .user_data = (void *)self
    };

    if(signal_context_set_crypto_provider(this->ctx, &crypto_provider) != 0){
        
        rb_bug("signal_context_set_crypto_provider()");
    }
        
    if(signal_context_set_locking_functions(this->ctx, global_lock, global_unlock) != 0){
        
        rb_bug("signal_context_set_locking_functions()");
    }    

    if(signal_context_set_log_function(this->ctx, global_log) != 0){
        
        rb_bug("signal_context_set_log_function()");
    }

    if(signal_protocol_store_context_create(&this->store_ctx, this->ctx) != 0){
        
        rb_bug("signal_protocol_store_context_create()");
    }

    const struct signal_protocol_session_store session_provider = {
        .load_session_func = get_session,
        .get_sub_device_sessions_func = get_session_ids,
        .store_session_func = post_session,
        .contains_session_func = session_exists,
        .delete_session_func = delete_session,
        .delete_all_sessions_func = delete_all_sessions,
        .destroy_func = destroy_func,
        .user_data = (void *)self        
    };    

    if(signal_protocol_store_context_set_session_store(this->store_ctx, &session_provider) != 0){
        
        rb_bug("signal_protocol_store_context_set_session_store()");
    }
    
    const struct signal_protocol_pre_key_store pre_key_provider = {
        .load_pre_key = get_pre_key,
        .store_pre_key = post_pre_key,
        .contains_pre_key = pre_key_exists,
        .remove_pre_key = delete_pre_key,
        .destroy_func = destroy_func,
        .user_data = (void *)self
    };
    
    if(signal_protocol_store_context_set_pre_key_store(this->store_ctx, &pre_key_provider) != 0){
        
        rb_bug("signal_protocol_store_context_set_pre_key_store()");
    }
    
    const struct signal_protocol_signed_pre_key_store signed_pre_key_provider = {
        .load_signed_pre_key = get_signed_pre_key,
        .store_signed_pre_key = post_signed_pre_key,
        .contains_signed_pre_key = signed_pre_key_exists,
        .remove_signed_pre_key = delete_signed_pre_key,
        .destroy_func = destroy_func,
        .user_data = (void *)self
    };
    
    if(signal_protocol_store_context_set_signed_pre_key_store(this->store_ctx, &signed_pre_key_provider) != 0){
     
        rb_bug("signal_protocol_store_context_set_signed_pre_key_store()");
    }
    
    const struct signal_protocol_identity_key_store identity_key_provider = {
        .get_identity_key_pair = get_identity_key_pair, 
        .get_local_registration_id = get_local_registration_id,
        .save_identity = post_identity,
        .is_trusted_identity = identity_is_trusted,
        .destroy_func = destroy_func,
        .user_data = (void *)self
    };
    
    if(signal_protocol_store_context_set_identity_key_store(this->store_ctx, &identity_key_provider) != 0){
     
        rb_bug("signal_protocol_store_context_set_identity_key_store()");
    }
    
    const struct signal_protocol_sender_key_store sender_key_provider = {
        .store_sender_key = post_sender_key,
        .load_sender_key = get_sender_key,
        .destroy_func = destroy_func,
        .user_data = (void *)self
    };
    
    if(signal_protocol_store_context_set_sender_key_store(this->store_ctx, &sender_key_provider) != 0){
 
        rb_bug("signal_protocol_store_context_set_sender_key_store()");
    }
    
    return self;
}

/* @return [IdentityKey]
 * 
 * */
static VALUE generate_identity_key_pair(VALUE self)
{
    VALUE retval, args;
    struct ext_client *this;        
    ratchet_identity_key_pair *identity_key_pair;    
    signal_buffer *buffer;
    int err;
    
    Data_Get_Struct(self, struct ext_client, this);
    
    if((err = signal_protocol_key_helper_generate_identity_key_pair(&identity_key_pair, this->ctx)) != 0){
        
        handle_error(err);        
    }
    
    args = rb_hash_new();    
    
    if((err = ratchet_identity_key_pair_serialize(&buffer, identity_key_pair)) != 0){
        
        ratchet_identity_key_pair_destroy((signal_type_base *)identity_key_pair);
        handle_error(err);
    }
    
    rb_hash_aset(args, ID2SYM(rb_intern("record")), buffer_to_rstring(buffer));
    signal_buffer_free(buffer);
    
    if((err = ec_public_key_serialize(&buffer, ratchet_identity_key_pair_get_public(identity_key_pair))) != 0){
        
        ratchet_identity_key_pair_destroy((signal_type_base *)identity_key_pair);
        handle_error(err);        
    }
            
    rb_hash_aset(args, ID2SYM(rb_intern("pub")), buffer_to_rstring(buffer));
    signal_buffer_free(buffer);
    
    if((err = ec_private_key_serialize(&buffer, ratchet_identity_key_pair_get_private(identity_key_pair))) != 0){
        
        ratchet_identity_key_pair_destroy((signal_type_base *)identity_key_pair);
        handle_error(err);        
    }
    
    rb_hash_aset(args, ID2SYM(rb_intern("priv")), buffer_to_rstring(buffer));
    signal_buffer_free(buffer);
    
    ratchet_identity_key_pair_destroy((signal_type_base *)identity_key_pair);
        
    return rb_funcall(rb_eval_string("IdentityKey"), rb_intern("new"), 1, args); 
}

/* @return [Integer]
 * 
 * */
static VALUE generate_registration_id(VALUE self)
{
    struct ext_client *this;            
    uint32_t id;
    int err;
    
    Data_Get_Struct(self, struct ext_client, this);
    
    if((err = signal_protocol_key_helper_generate_registration_id(&id, 1, this->ctx)) != 0){
        
        handle_error(err);
    }
    
    return UINT2NUM(id);
}

#if 0
static VALUE generate_key_pair(VALUE self)
{
    VALUE retval;
    struct ext_client *this;            
    signal_buffer *pub_buf, *priv_buf;    
    ec_key_air *key_pair;
    int err;
    
    Data_Get_Struct(self, struct ext_client, this);
    
    VALUE args = rb_hash_new();    
    
    if((err = curve_generate_key_pair(this->ctx, &key_pair)) != 0){
    
        handle_error(err);
    }
    
    if((err = ec_public_key_serialize(&buffer, ec_key_pair_get_public(key_pair))) != 0){
        
        ec_key_pair_destroy((signal_type_base *)key_pair);
        handle_error(err);
    }
    
    rb_hash_aset(args, ID2SYM(rb_intern("pub")), buffer_to_rstring(buffer));
    signal_buffer_free(buffer);
    
    if((err = ec_private_key_serialize(&buffer, ec_key_pair_get_private(key_pair))) != 0){
        
        ec_key_pair_destroy((signal_type_base *)key_pair);
        handle_error(err);
    }
    
    rb_hash_aset(args, ID2SYM(rb_intern("priv")), buffer_to_rstring(buffer));
    signal_buffer_free(buffer);
        
    retval = rb_funcall(rb_eval_string("IdentityKey"), rb_intern("new"), 1, args);
    
    ec_key_pair_destroy((signal_type_base *)key_pair);
    
    return retval;
}
#endif

/* @param start_id [Integer] 16 bit unsigned
 * @param number_of_keys [Integer] 16 bit unsigned
 * @return [Array<PreKey>] array of prekey objects
 * 
 * */
static VALUE generate_pre_keys(VALUE self, VALUE start_id, VALUE number_of_keys)
{
    VALUE retval;
    struct ext_client *this;            
    signal_protocol_key_helper_pre_key_list_node *head, *node;
    session_pre_key *pre_key;
    signal_buffer *buffer;
    int err;
    
    Data_Get_Struct(self, struct ext_client, this);
    
    if(rb_obj_is_kind_of(start_id, rb_cInteger) != Qtrue){
        
        rb_raise(rb_eTypeError, "start_id must be an integer");
    }
    else{
    
        if((NUM2LL(start_id) < 0) || (NUM2LL(start_id) > UINT16_MAX)){
            
            rb_raise(rb_eRangeError, "start_id must be in range 0..65535");
        }        
    }
    
    if(rb_obj_is_kind_of(number_of_keys, rb_cInteger) != Qtrue){
        
        rb_raise(rb_eTypeError, "number_of_keys must be an integer");
    }
    else{
    
        if((NUM2LL(number_of_keys) < 0) || (NUM2LL(number_of_keys) > UINT16_MAX)){
            
            rb_raise(rb_eRangeError, "number_of_keys must be in range 0..65535");
        }        
    }
    
    if((err = signal_protocol_key_helper_generate_pre_keys(&head, NUM2UINT(start_id), NUM2UINT(number_of_keys), this->ctx)) != 0){
        
        handle_error(err);
    }
    
    retval = rb_ary_new();
    
    node = head;
    
    while(node != NULL){
    
        pre_key = signal_protocol_key_helper_key_list_element(node);
        
        VALUE args = rb_hash_new();
        
        if((err = session_pre_key_serialize(&buffer, pre_key)) != 0){
        
            signal_protocol_key_helper_key_list_free(head);
            handle_error(err);
        }
        
        rb_hash_aset(args, ID2SYM(rb_intern("id")), UINT2NUM(session_pre_key_get_id(pre_key))); 
        rb_hash_aset(args, ID2SYM(rb_intern("record")), buffer_to_rstring(buffer)); 
        signal_buffer_free(buffer);
        
        if((err = ec_public_key_serialize(&buffer, ec_key_pair_get_public(session_pre_key_get_key_pair(pre_key)))) != 0){
            
            handle_error(err);
        }
        
        rb_hash_aset(args, ID2SYM(rb_intern("pub")), buffer_to_rstring(buffer)); 
        signal_buffer_free(buffer);
        
        if((err = ec_private_key_serialize(&buffer, ec_key_pair_get_private(session_pre_key_get_key_pair(pre_key)))) != 0){
            
            handle_error(err);
        }
                
        rb_hash_aset(args, ID2SYM(rb_intern("priv")), buffer_to_rstring(buffer)); 
        signal_buffer_free(buffer);
                
        rb_ary_push(retval, rb_funcall(rb_eval_string("PreKey"), rb_intern("new"), 1, args));
        
        node = signal_protocol_key_helper_key_list_next(node);        
    }
    
    signal_protocol_key_helper_key_list_free(head);
    
    return retval;
}

/* @param identity_key_pair [IdentityKey]
 * @param signed_pre_key_id [Integer] (0..4294967295)
 * @return [String]
 * 
 * */
static VALUE generate_signed_pre_key(VALUE self, VALUE identity_key_pair, VALUE signed_pre_key_id)
{
    VALUE retval, args;
    struct ext_client *this;            
    session_signed_pre_key *signed_pre_key;
    ratchet_identity_key_pair *ratchet;
    signal_buffer *buffer;
    int err;
    
    Data_Get_Struct(self, struct ext_client, this);

    if(rb_obj_is_instance_of(identity_key_pair, rb_eval_string("IdentityKey")) != Qtrue){
        
        rb_raise(rb_eTypeError, "identity_key_pair must be an instance of IdentityKey");
    }
    
    if(rb_obj_is_kind_of(signed_pre_key_id, rb_cInteger) != Qtrue){
        
        rb_raise(rb_eTypeError, "signed_pre_key_id must be an integer");
    }
    else{
    
        if((NUM2LL(signed_pre_key_id) < 0) || (NUM2LL(signed_pre_key_id) > UINT32_MAX)){
            
            rb_raise(rb_eRangeError, "signed_pre_key_id must be in range 0..4294967295");
        }        
    }
    
    if((err = ratchet_identity_key_pair_create(&ratchet, 
        rstring_to_ec_public_key(this->ctx, rb_funcall(identity_key_pair, rb_intern("pub"), 0)),
        rstring_to_ec_private_key(this->ctx, rb_funcall(identity_key_pair, rb_intern("priv"), 0))
    )) != 0){
        
        handle_error(err);
    }
    
    if((err = signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, ratchet, NUM2UINT(signed_pre_key_id), my_get_time(), this->ctx)) != 0){ 
       
        ratchet_identity_key_pair_destroy((signal_type_base *)ratchet);
        handle_error(err);
    }
    
    ratchet_identity_key_pair_destroy((signal_type_base *)ratchet);
    
    args = rb_hash_new();
    
    if((err = session_signed_pre_key_serialize(&buffer, signed_pre_key)) != 0){
    
        session_pre_key_destroy((signal_type_base *)signed_pre_key);
        handle_error(err);
    }
    
    rb_hash_aset(args, ID2SYM(rb_intern("record")), buffer_to_rstring(buffer));
    signal_buffer_free(buffer);

    if((err = ec_public_key_serialize(&buffer, ec_key_pair_get_public(session_signed_pre_key_get_key_pair(signed_pre_key)))) != 0){
    
        ec_key_pair_destroy((signal_type_base *)signed_pre_key);
        handle_error(err);
    }
    
    rb_hash_aset(args, ID2SYM(rb_intern("pub")), buffer_to_rstring(buffer));
    signal_buffer_free(buffer);
    
    if((err = ec_private_key_serialize(&buffer, ec_key_pair_get_private(session_signed_pre_key_get_key_pair(signed_pre_key)))) != 0){
        
        ec_key_pair_destroy((signal_type_base *)signed_pre_key);
        handle_error(err);
    }
    
    rb_hash_aset(args, ID2SYM(rb_intern("priv")), buffer_to_rstring(buffer));
    signal_buffer_free(buffer);
    
    rb_hash_aset(args, ID2SYM(rb_intern("id")), UINT2NUM(session_signed_pre_key_get_id(signed_pre_key)));    
    rb_hash_aset(args, ID2SYM(rb_intern("timestamp")), ULL2NUM(session_signed_pre_key_get_timestamp(signed_pre_key)));
    rb_hash_aset(args, ID2SYM(rb_intern("signature")), rb_str_new((char *)session_signed_pre_key_get_signature(signed_pre_key), session_signed_pre_key_get_signature_len(signed_pre_key)));
    
    session_pre_key_destroy((signal_type_base *)signed_pre_key);
    
    return rb_funcall(rb_eval_string("SignedPreKey"), rb_intern("new"), 1, args);    
}

/* Create a session with remote client
 * 
 * @param remote_bundle [PreKeyBundle]
 * 
 * @return [self]
 * 
 * */
static VALUE add_session(VALUE self, VALUE pre_key_bundle)
{
    struct ext_client *this;            
    session_pre_key_bundle *bundle;
    session_builder *builder;
    int err;
    
    Data_Get_Struct(self, struct ext_client, this);

    if(rb_obj_is_instance_of(pre_key_bundle, rb_eval_string("PreKeyBundle")) != Qtrue){
        
        rb_raise(rb_eTypeError, "pre_key_bundle must be an instance of PreKeyBundle");
    }

    if((err = session_pre_key_bundle_create(&bundle,
        NUM2UINT(rb_funcall(pre_key_bundle, rb_intern("registration_id"), 0)),
        NUM2INT(rb_funcall(pre_key_bundle, rb_intern("device_id"), 0)),
        NUM2UINT(rb_funcall(pre_key_bundle, rb_intern("pre_key_id"), 0)),
        rstring_to_ec_public_key(this->ctx, rb_funcall(pre_key_bundle, rb_intern("pre_key_pub"), 0)),
        NUM2UINT(rb_funcall(pre_key_bundle, rb_intern("signed_pre_key_id"), 0)),
        rstring_to_ec_public_key(this->ctx, rb_funcall(pre_key_bundle, rb_intern("signed_pre_key_pub"), 0)),
        (uint8_t *)RSTRING_PTR(rb_funcall(pre_key_bundle, rb_intern("signed_pre_key_sig"), 0)),
        RSTRING_LEN(rb_funcall(pre_key_bundle, rb_intern("signed_pre_key_sig"), 0)),
        rstring_to_ec_public_key(this->ctx, rb_funcall(pre_key_bundle, rb_intern("identity_key_pub"), 0))
    )) != 0){
        
        handle_error(err);
    }
    
    signal_protocol_address address = {
        .name = RSTRING_PTR(rb_funcall(pre_key_bundle, rb_intern("name"), 0)), 
        .name_len = RSTRING_LEN(rb_funcall(pre_key_bundle, rb_intern("name"), 0)), 
        .device_id = NUM2UINT(rb_funcall(pre_key_bundle, rb_intern("device_id"), 0))
    };
    
    if((err = session_builder_create(&builder, this->store_ctx, &address, this->ctx)) != 0){
        
        session_pre_key_bundle_destroy((signal_type_base *)bundle);
        handle_error(err);
    }

    if((err = session_builder_process_pre_key_bundle(builder, bundle)) != 0){
        
        session_pre_key_bundle_destroy((signal_type_base *)bundle);
        session_builder_free(builder);
        handle_error(err);
    }
        
    session_pre_key_bundle_destroy((signal_type_base *)bundle);
    session_builder_free(builder);
    
    return self;
}

/* Encode a message
 * 
 * @param address [LibSignal::Address]
 * @param message [String]
 * 
 * @return [String]
 * 
 * */
VALUE encode(VALUE self, VALUE address, VALUE message)
{
    return self;
}

/* other **************************************************************/

static uint64_t my_get_time(void)
{
    uint64_t retval;
    struct timespec ts;
    
    rb_timespec_now(&ts);
    
    retval = ts.tv_sec;
    retval *= 1000;
    retval += (ts.tv_nsec / 1000000);
    
    return retval;
}

static void free_state(void *p)
{
    struct ext_client *this = (struct ext_client *)p;
    
    if(this->store_ctx != NULL){
        
        signal_protocol_store_context_destroy(this->store_ctx);
    }
    
    if(this->ctx != NULL){
        
        signal_context_destroy(this->ctx);
    }
    
    free(p);
}

static VALUE alloc_state(VALUE klass)
{
    return Data_Wrap_Struct(klass, 0, free_state, calloc(1, sizeof(struct ext_client)));
}

static VALUE copy_state(VALUE copy, VALUE orig) 
{
    if((TYPE(orig) != T_DATA) || (RDATA(orig)->dfree != (RUBY_DATA_FUNC)free_state)){
        
        rb_raise(rb_eTypeError, "wrong argument type");
    }
    
    return initialize(copy, rb_funcall(orig, rb_intern("data"), 0));
}

static VALUE buffer_to_rstring(const signal_buffer *buffer)
{
    return rb_str_new((char *)signal_buffer_const_data(buffer), signal_buffer_len(buffer));
}

static signal_buffer *rstring_to_buffer(VALUE str)
{
    signal_buffer *retval;
    
    retval = signal_buffer_create((uint8_t *)RSTRING_PTR(str), (size_t)RSTRING_LEN(str));
    
    if(retval == NULL){
        
        rb_raise(rb_eNoMemError, "rstring_to_buffer()");
    }
    
    return retval;
}

static ec_public_key *rstring_to_ec_public_key(signal_context *ctx, VALUE str)
{
    int err;
    ec_public_key *retval;
    
    if((err = curve_decode_point(&retval, (uint8_t *)RSTRING_PTR(str), RSTRING_LEN(str), ctx)) != 0){
        
        handle_error(err);
    } 
    
    return retval; 
}

static ec_private_key *rstring_to_ec_private_key(signal_context *ctx, VALUE str)
{
    ec_private_key *retval;
    int err;
    
    if((err = curve_decode_private_point(&retval, (uint8_t *)RSTRING_PTR(str), RSTRING_LEN(str), ctx)) != 0){
        
        handle_error(err);
    } 
    
    return retval; 
}

static void handle_error(int error)
{
    VALUE ex = Qnil;
    
    switch(error){
    default:
    case SG_ERR_UNKNOWN:      
        ex = eErrUnknown;
        break;
    case SG_ERR_DUPLICATE_MESSAGE:
        ex = eErrDuplicateMessage;    
        break;
    case SG_ERR_INVALID_KEY:
        ex = eErrInvalidKey;
        break;
    case SG_ERR_INVALID_KEY_ID:
        ex = eErrInvalidKeyID;
        break;
    case SG_ERR_INVALID_MAC:
        ex = eErrInvalidMAC;
        break;
    case SG_ERR_INVALID_MESSAGE:
        ex = eErrInvalidMessage;
        break;
    case SG_ERR_INVALID_VERSION:
        ex = eErrInvalidVersion;
        break;
    case SG_ERR_LEGACY_MESSAGE:
        ex = eErrLegacyMessage;
        break;
    case SG_ERR_NO_SESSION:
        ex = eErrNoSession;
        break;
    case SG_ERR_STALE_KEY_EXCHANGE:
        ex = eErrStaleKeyExchange;
        break;
    case SG_ERR_UNTRUSTED_IDENTITY:
        ex = eErrUntrustedIdentity;
        break;
    case SG_ERR_VRF_SIG_VERIF_FAILED:
        ex = eErrVRFSigVerifFailed;
        break;
    case SG_ERR_INVALID_PROTO_BUF:
        ex = eErrInvalidProtoBuf;
        break;
    case SG_ERR_FP_VERSION_MISMATCH:
        ex = eErrFPIdentMismatch;
        break;
    case SG_ERR_FP_IDENT_MISMATCH:
        ex = eErrFPIdentMismatch;
        break;
    case SG_ERR_NOMEM:
        ex = rb_eNoMemError;
        break;        
    case SG_ERR_INVAL:
        ex = rb_eArgError;
        break;
    case SG_SUCCESS:
        break;
    }
    
    if(ex != Qnil){
    
        rb_raise(ex, "error code %i", error);
    }
}

void Init_ext_lib_signal(void)
{
    VALUE cLibSignal;
    VALUE cExtClient;
    
    rb_require("openssl");
    rb_require("monitor");

    cLibSignal = rb_define_module("LibSignal");    
    cExtClient = rb_define_class_under(cLibSignal, "ExtClient", rb_cObject);
    
    rb_define_alloc_func(cExtClient, alloc_state);
    
    rb_define_method(cExtClient, "initialize", initialize, 1);
    rb_define_method(cExtClient, "initialize_copy", copy_state, 1);
    
    rb_define_method(cExtClient, "generate_identity_key_pair", generate_identity_key_pair, 0);
    rb_define_method(cExtClient, "generate_registration_id", generate_registration_id, 0);
    rb_define_method(cExtClient, "generate_pre_keys", generate_pre_keys, 2);
    rb_define_method(cExtClient, "generate_signed_pre_key", generate_signed_pre_key, 2);        
 
    rb_define_method(cExtClient, "add_session", add_session, 1);        
    rb_define_method(cExtClient, "encode", encode, 2);        
    
    
    eErrUnknown = rb_define_class_under(cLibSignal, "ErrUnknown", rb_eStandardError);
    eErrDuplicateMessage = rb_define_class_under(cLibSignal, "ErrDuplicateMessage", rb_eStandardError);
    eErrInvalidKey = rb_define_class_under(cLibSignal, "ErrInvalidKey", rb_eStandardError);
    eErrInvalidKeyID = rb_define_class_under(cLibSignal, "ErrInvalidKeyID", rb_eStandardError);
    eErrInvalidMAC = rb_define_class_under(cLibSignal, "ErrInvalidMac", rb_eStandardError);
    eErrInvalidMessage = rb_define_class_under(cLibSignal, "ErrInvalidMessage", rb_eStandardError);
    eErrInvalidVersion = rb_define_class_under(cLibSignal, "ErrInvalidVersion", rb_eStandardError);
    eErrLegacyMessage = rb_define_class_under(cLibSignal, "ErrLegacyMessage", rb_eStandardError);
    eErrNoSession = rb_define_class_under(cLibSignal, "ErrNoSession", rb_eStandardError);
    eErrStaleKeyExchange = rb_define_class_under(cLibSignal, "ErrStaleKeyExchange", rb_eStandardError);
    eErrUntrustedIdentity = rb_define_class_under(cLibSignal, "ErrUntrustedIdentity", rb_eStandardError);
    eErrVRFSigVerifFailed = rb_define_class_under(cLibSignal, "ErrVRFSigVerifFailed", rb_eStandardError);
    eErrInvalidProtoBuf = rb_define_class_under(cLibSignal, "ErrInvalidProtoBuf", rb_eStandardError);
    eErrFPVersionMismatch = rb_define_class_under(cLibSignal, "ErrFPVersionMismatch", rb_eStandardError);
    eErrFPIdentMismatch = rb_define_class_under(cLibSignal, "ErrFPIdentMismatch", rb_eStandardError);
}

