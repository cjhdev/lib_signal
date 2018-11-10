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
        2, 
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
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("get_session_ids"), 1, rb_str_new((char *)name, name_len));
        
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

    rb_iv_set(self, "@refs", rb_ary_new());
    rb_iv_set(self, "@data", data);
    rb_iv_set(self, "@global_lock", rb_funcall(rb_eval_string("Monitor"), rb_intern("new"), 0));
    
    if(signal_context_create(&this->ctx, (void *)self) != 0){
        
        rb_bug("signal_context_create()");
    }

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

static VALUE generate_identity_key_pair(VALUE self)
{
    VALUE retval;
    struct ext_client *this;        
    ratchet_identity_key_pair *identity_key_pair;    
    signal_buffer *buffer;
    
    Data_Get_Struct(self, struct ext_client, this);
    
    if(signal_protocol_key_helper_generate_identity_key_pair(&identity_key_pair, this->ctx) != 0){
        
        rb_bug("signal_protocol_key_helper_generate_identity_key_pair()");
    }
    
    retval = rb_eval_string("KeyPair.new");
    
    ec_public_key_serialize(&buffer, ratchet_identity_key_pair_get_public(identity_key_pair));
    rb_funcall(retval, rb_intern("pub="), 1, buffer_to_rstring(buffer));
    signal_buffer_free(buffer);
    
    ec_private_key_serialize(&buffer, ratchet_identity_key_pair_get_private(identity_key_pair));
    rb_funcall(retval, rb_intern("priv="), 1, buffer_to_rstring(buffer));
    signal_buffer_free(buffer);
    
    ratchet_identity_key_pair_destroy((signal_type_base *)identity_key_pair);
    
    return retval;
}

static VALUE generate_registration_id(VALUE self, VALUE extended)
{
    struct ext_client *this;            
    uint32_t id;
    
    Data_Get_Struct(self, struct ext_client, this);
    
    if(signal_protocol_key_helper_generate_registration_id(&id, (extended == Qtrue) ? 1 : 0, this->ctx) != 0){
        
        rb_bug("signal_protocol_key_helper_generate_registration_id()");
    }
    
    return UINT2NUM(id);
}

static VALUE generate_pre_keys(VALUE self, VALUE start_id, VALUE number_of_keys)
{
    VALUE retval;
    struct ext_client *this;            
    signal_protocol_key_helper_pre_key_list_node *head, *node;
    session_pre_key *pre_key;
    signal_buffer *buffer;
    
    Data_Get_Struct(self, struct ext_client, this);
    
    if(signal_protocol_key_helper_generate_pre_keys(&head, NUM2UINT(start_id), NUM2UINT(number_of_keys), this->ctx) != 0){
        
        rb_bug("signal_protocol_key_helper_generate_pre_keys()");
    }
    
    retval = rb_ary_new();
    
    node = head;
    
    while(node != NULL){
    
        pre_key = signal_protocol_key_helper_key_list_element(node);
        
        assert(pre_key != NULL);
        
        if(session_pre_key_serialize(&buffer, pre_key) != 0){
            
            rb_bug("session_pre_key_serialize()");
        }
        
        rb_ary_push(retval, buffer_to_rstring(buffer));
        
        signal_buffer_free(buffer);
        
        node = signal_protocol_key_helper_key_list_next(node);        
    }
    
    signal_protocol_key_helper_key_list_free(head);
    
    return retval;
}

static VALUE generate_signed_pre_key(VALUE self, VALUE identity_key_pair, VALUE signed_pre_key_id)
{
    VALUE retval;
    struct ext_client *this;            
    session_signed_pre_key *pre_key;
    ratchet_identity_key_pair *ratchet;
    signal_buffer *buffer;
    
    Data_Get_Struct(self, struct ext_client, this);

    if(ratchet_identity_key_pair_create(&ratchet, 
        rstring_to_ec_public_key(this->ctx, rb_funcall(identity_key_pair, rb_intern("pub"), 0)),
        rstring_to_ec_private_key(this->ctx, rb_funcall(identity_key_pair, rb_intern("priv"), 0))
    ) != 0){
        
        rb_bug("ratchet_identity_key_pair_create");
    }
    
    if(signal_protocol_key_helper_generate_signed_pre_key(&pre_key, ratchet, NUM2UINT(signed_pre_key_id), my_get_time(), this->ctx) != 0){ 
       
        rb_bug("signal_protocol_key_helper_generate_signed_pre_key()");
    }
    
    if(session_signed_pre_key_serialize(&buffer, pre_key) != 0){
        
        rb_bug("session_signed_pre_key_serialize()");
    }
    
    retval = buffer_to_rstring(buffer);
    
    ratchet_identity_key_pair_destroy((signal_type_base *)ratchet);
    session_pre_key_destroy((signal_type_base *)pre_key);
    signal_buffer_free(buffer);
    
    return retval;    
}

#if 0
static VALUE sign(VALUE self, VALUE private_key, VALUE data)
{
    struct ext_client *this;                
    signal_buffer *signature;
    ec_private_key *k;
    VALUE retval;
    
    Data_Get_Struct(self, struct ext_client, this);
    
    k = rstring_to_ec_private_key(private_key);
    
    curve_calculate_signature(this->ctx, 
        &signature,
        k,
        (uint8_t *)RSTRING_PTR(data), RSTRING_LEN(data)
    );
    
    retval = buffer_to_rstring(signature);
    
    ec_private_key_destroy((signal_base_type *)k);
    signal_buffer_free(signature);
    
    return retval;    
}
#endif

#if 0
static VALUE create_registration_bundle(VALUE self, 
    VALUE registration_id, 
    VALUE device_id,
    VALUE identity_key_pub,
    VALUE signed_pre_key,
)
{
    struct ext_client *this;                
    session_signed_pre_key *spk;
    
    Data_Get_Struct(self, struct ext_client, this);
    
    if(session_signed_pre_key_deserialize(&spk, RSTRING_PTR(signed_pre_key), RSTRING_LEN(signed_pre_key), this->ctx) != 0){
        
        rb_bug("session_signed_pre_key_deserialize");
    }
    
    UINT2NUM(registration_id)
    
    INT
    
    // signed_pre_key_id
    UINT2NUM(session_signed_pre_key_get_id(spk))
    
    // signature
    rb_str_new((char *)session_signed_pre_key_get_signature(spk), session_signed_pre_key_get_signature_len(spk));
    
    // signed_pre_key_pub
    if(ec_public_key_serialize(&buffer, ec_key_pair_get_public(session_signed_pre_key_get_key_pair(spk))) != 0){
        
        rb_bug("ec_public_key_serialize()");
    }
    
    
    
    
    session_signed_pre_key
    session_signed_pre_key
    
}
#endif

static VALUE add_session(VALUE self, VALUE remote_bundle)
{
    struct ext_client *this;            
    session_pre_key_bundle *bundle;
    session_builder *builder;
    
    Data_Get_Struct(self, struct ext_client, this);

    if(session_pre_key_bundle_create(&bundle,
        NUM2UINT(rb_funcall(remote_bundle, rb_intern("registration_id"), 0)),
        NUM2INT(rb_funcall(remote_bundle, rb_intern("device_id"), 0)),
        NUM2UINT(rb_funcall(remote_bundle, rb_intern("pre_key_id"), 0)),
        rstring_to_ec_public_key(this->ctx, rb_funcall(remote_bundle, rb_intern("pre_key_pub"), 0)),
        NUM2UINT(rb_funcall(remote_bundle, rb_intern("signed_pre_key_id"), 0)),
        rstring_to_ec_public_key(this->ctx, rb_funcall(remote_bundle, rb_intern("signed_pre_key_pub"), 0)),
        (uint8_t *)RSTRING_PTR(rb_funcall(remote_bundle, rb_intern("signed_pre_key_sig"), 0)),
        RSTRING_LEN(rb_funcall(remote_bundle, rb_intern("signed_pre_key_sig"), 0)),
        rstring_to_ec_public_key(this->ctx, rb_funcall(remote_bundle, rb_intern("identity_key_pub"), 0))
    ) != 0){
        rb_bug("session_pre_key_bundle_create");
    }
    
    signal_protocol_address address = {
        .name = RSTRING_PTR(rb_funcall(remote_bundle, rb_intern("name"), 0)), 
        .name_len = RSTRING_LEN(rb_funcall(remote_bundle, rb_intern("name"), 0)), 
        .device_id = NUM2UINT(rb_funcall(remote_bundle, rb_intern("device_id"), 0))
    };
    
    if(session_builder_create(&builder, this->store_ctx, &address, this->ctx) != 0){
        
        rb_bug("session_builder_create");
    }

    if(session_builder_process_pre_key_bundle(builder, bundle) != 0){
        
        rb_bug("session_builder_process_pre_key_bundle");
    }
    
    session_builder_free(builder);
    session_pre_key_bundle_destroy((signal_type_base *)bundle);
    
    return Qnil;
}

VALUE encode(VALUE self, VALUE address, VALUE message)
{
    struct ext_client *this;            
    session_cipher *cipher;
    ciphertext_message *encrypted_message;
    VALUE retval;
    
    Data_Get_Struct(self, struct ext_client, this);

    signal_protocol_address addr = {
        .name = RSTRING_PTR(rb_funcall(address, rb_intern("name"), 0)), 
        .name_len = RSTRING_LEN(rb_funcall(address, rb_intern("name"), 0)), 
        .device_id = NUM2UINT(rb_funcall(address, rb_intern("device_id"), 0))
    };

    session_cipher_create(&cipher, this->store_ctx, &addr, this->ctx);

    session_cipher_encrypt(cipher, (uint8_t *)RSTRING_PTR(message), RSTRING_LEN(message), &encrypted_message);

    retval = buffer_to_rstring(ciphertext_message_get_serialized(encrypted_message));

    return retval;
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
    return signal_buffer_create((uint8_t *)RSTRING_PTR(str), (size_t)RSTRING_LEN(str));
}

static ec_public_key *rstring_to_ec_public_key(signal_context *ctx, VALUE str)
{
    ec_public_key *retval;
    
    if(curve_decode_point(&retval, (uint8_t *)RSTRING_PTR(str), RSTRING_LEN(str), ctx) != 0){
        
        rb_bug("curve_decode_point");
    } 
    
    return retval; 
}

static ec_private_key *rstring_to_ec_private_key(signal_context *ctx, VALUE str)
{
    ec_private_key *retval;
    
    if(curve_decode_private_point(&retval, (uint8_t *)RSTRING_PTR(str), RSTRING_LEN(str), ctx) != 0){
        
        rb_bug("curve_decode_private_point");
    } 
    
    return retval; 
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
    rb_define_method(cExtClient, "generate_registration_id", generate_registration_id, 1);
    rb_define_method(cExtClient, "generate_pre_keys", generate_pre_keys, 2);
    rb_define_method(cExtClient, "generate_signed_pre_key", generate_signed_pre_key, 2);        
 
    rb_define_method(cExtClient, "add_session", add_session, 1);        
    rb_define_method(cExtClient, "encode", encode, 2);        
}
