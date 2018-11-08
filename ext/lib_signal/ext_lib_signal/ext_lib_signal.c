#include "signal_protocol.h"
#include "key_helper.h"
#include "converters.h"
#include <ruby.h>
#include <assert.h>
#include <stdbool.h>

int random_func(uint8_t *data, size_t len, void *user_data);
int hmac_sha256_init_func(void **context, const uint8_t *key, size_t key_len, void *user_data);
int sha512_digest_init_func(void **context, void *user_data);
int digest_update_func(void *context, const uint8_t *data, size_t data_len, void *user_data);
int digest_final_func(void *context, signal_buffer **output, void *user_data);
void digest_cleanup_func(void *context, void *user_data);
int encrypt_func(signal_buffer **output,
    int cipher,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *plaintext, size_t plaintext_len,
    void *user_data);
int decrypt_func(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len,
        void *user_data);

int load_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data);
int store_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data);
int contains_pre_key(uint32_t pre_key_id, void *user_data);
int remove_pre_key(uint32_t pre_key_id, void *user_data);

int load_signed_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data);
int store_signed_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data);
int contains_signed_pre_key(uint32_t pre_key_id, void *user_data);
int remove_signed_pre_key(uint32_t pre_key_id, void *user_data);

void global_lock(void *user_data);
void global_unlock(void *user_data);

void global_log(int level, const char *message, size_t len, void *user_data);

int store_sender_key(const signal_protocol_sender_key_name *sender_key_name, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data);
int load_sender_key(signal_buffer **record, signal_buffer **user_record, const signal_protocol_sender_key_name *sender_key_name, void *user_data);

int get_identity_key_pair(signal_buffer **public_data, signal_buffer **private_data, void *user_data);
int get_local_registration_id(void *user_data, uint32_t *registration_id);
int save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);
int is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);

int my_get_session(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data);
int my_get_all_sessions(signal_int_list **sessions, const char *name, size_t name_len, void *user_data);
int my_put_session(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data);
int my_session_exists(const signal_protocol_address *address, void *user_data);
int my_delete_session(const signal_protocol_address *address, void *user_data);
int my_delete_all_sessions(const char *name, size_t name_len, void *user_data);

static VALUE cLibSignal;
static VALUE cExtClient;

struct ext_client {
    
    signal_context *ctx;
    signal_protocol_store_context *store_ctx;
};

static VALUE alloc_state(VALUE klass)
{
    return Data_Wrap_Struct(klass, 0, free, calloc(1, sizeof(struct ext_client)));
}

/* dummy destroy function since Ruby will take care of all of that elsewhere */
static void destroy_func(void *user_data)
{
}

static VALUE initialize(VALUE self)
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
        .encrypt_func = encrypt_func,
        .decrypt_func = decrypt_func,
        .user_data = (void *)self
    };

    rb_iv_set(self, "@refs", rb_ary_new());
    rb_iv_set(self, "@global_lock", rb_funcall(rb_const_get(rb_cObject, rb_intern("Monitor")), rb_intern("new"), 0));
    
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
        .load_session_func = my_get_session,
        .get_sub_device_sessions_func = my_get_all_sessions,
        .store_session_func = my_put_session,
        .contains_session_func = my_session_exists,
        .delete_session_func = my_delete_session,
        .delete_all_sessions_func = my_delete_all_sessions,
        .destroy_func = destroy_func,
        .user_data = (void *)self        
    };    

    if(signal_protocol_store_context_set_session_store(this->store_ctx, &session_provider) != 0){
        
        rb_bug("signal_protocol_store_context_set_session_store()");
    }
    
    const struct signal_protocol_pre_key_store pre_key_provider = {
        .load_pre_key = load_pre_key,
        .store_pre_key = store_pre_key,
        .contains_pre_key = contains_pre_key,
        .remove_pre_key = remove_pre_key,
        .destroy_func = destroy_func,
        .user_data = (void *)self
    };
    
    if(signal_protocol_store_context_set_pre_key_store(this->store_ctx, &pre_key_provider) != 0){
        
        rb_bug("signal_protocol_store_context_set_pre_key_store()");
    }
    
    const struct signal_protocol_signed_pre_key_store signed_pre_key_provider = {
        .load_signed_pre_key = load_pre_key,
        .store_signed_pre_key = store_pre_key,
        .contains_signed_pre_key = contains_pre_key,
        .remove_signed_pre_key = remove_pre_key,
        .destroy_func = destroy_func,
        .user_data = (void *)self
    };
    
    if(signal_protocol_store_context_set_signed_pre_key_store(this->store_ctx, &signed_pre_key_provider) != 0){
     
        rb_bug("signal_protocol_store_context_set_signed_pre_key_store()");
    }
    
    const struct signal_protocol_identity_key_store identity_key_provider = {
        .get_identity_key_pair = get_identity_key_pair, 
        .get_local_registration_id = get_local_registration_id,
        .save_identity = save_identity,
        .is_trusted_identity = is_trusted_identity,
        .destroy_func = destroy_func,
        .user_data = (void *)self
    };
    
    if(signal_protocol_store_context_set_identity_key_store(this->store_ctx, &identity_key_provider) != 0){
     
        rb_bug("signal_protocol_store_context_set_identity_key_store()");
    }
    
    const struct signal_protocol_sender_key_store sender_key_provider = {
        .store_sender_key = store_sender_key,
        .load_sender_key = load_sender_key,
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
    
    if(ratchet_identity_key_pair_serialize(&buffer, identity_key_pair) != 0){        
        
        rb_bug("ratchet_identity_key_pair_serialize()");
    }
    
    retval = buffer_to_rstring(buffer);    
    
    ratchet_identity_key_pair_destroy((signal_type_base *)identity_key_pair);
    signal_buffer_free(buffer);
    
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

static VALUE generate_pre_keys(VALUE self, VALUE start_id, VALUE number)
{
    VALUE retval;
    struct ext_client *this;            
    signal_protocol_key_helper_pre_key_list_node *head, *node;
    session_pre_key *pre_key;
    signal_buffer *buffer;
    
    Data_Get_Struct(self, struct ext_client, this);
    
    if(signal_protocol_key_helper_generate_pre_keys(&head, NUM2UINT(start_id), NUM2UINT(number), this->ctx) != 0){
        
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

static VALUE generate_signed_pre_key(VALUE self, VALUE identity_key_pair, VALUE signed_pre_key_id)
{
    VALUE retval;
    struct ext_client *this;            
    session_signed_pre_key *pre_key;
    ratchet_identity_key_pair *ratchet;
    signal_buffer *buffer;
    
    Data_Get_Struct(self, struct ext_client, this);
    
    if(ratchet_identity_key_pair_deserialize(&ratchet, (uint8_t *)RSTRING_PTR(identity_key_pair), RSTRING_LEN(identity_key_pair), this->ctx) != 0){
     
        rb_bug("ratchet_identity_key_pair_deserialize()");
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

void Init_ext_lib_signal(void)
{
    rb_require("openssl");

    cLibSignal = rb_define_module("LibSignal");    
    cExtClient = rb_define_class_under(cLibSignal, "ExtClient", rb_cObject);
    
    rb_define_alloc_func(cExtClient, alloc_state);
    
    rb_define_method(cExtClient, "initialize", initialize, 0);
    
    rb_define_method(cExtClient, "generate_identity_key_pair", generate_identity_key_pair, 0);
    rb_define_method(cExtClient, "generate_registration_id", generate_registration_id, 1);
    rb_define_method(cExtClient, "generate_pre_keys", generate_pre_keys, 2);
    rb_define_method(cExtClient, "generate_signed_pre_key", generate_signed_pre_key, 2);        
}
