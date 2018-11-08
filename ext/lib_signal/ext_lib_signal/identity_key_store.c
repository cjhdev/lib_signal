#include <ruby.h>
#include "signal_protocol.h"

int get_identity_key_pair(signal_buffer **public_data, signal_buffer **private_data, void *user_data)
{
    int retval = -1;

    VALUE result = rb_funcall((VALUE)user_data, rb_intern("get_identity_key_pair"), 0);
    
    if(result != Qnil){
    
        *public_data = rstring_to_buffer(rb_ary_entry(result, 0));
        *private_data = rstring_to_buffer(rb_ary_entry(result, 1));
    
        retval = 0;
    }    
        
    return retval;
}

int get_local_registration_id(void *user_data, uint32_t *registration_id)
{
    int retval = -1;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("get_local_registration_id"), 0);
    
    return retval;
}

int save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    int retval = -1;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("save_identity"), 0);
    
    return retval;
}

int is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    int retval = -1;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("is_trusted_identity?"), 0);
    
    return retval;
}
