#include <ruby.h>
#include "signal_protocol.h"

int load_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data)
{
    int retval = 0;

    VALUE result = rb_funcall((VALUE)user_data, rb_intern("load_pre_key"), 0);
    
    return retval;
}

int store_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
    int retval = 0;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("store_pre_key"), 0);
    
    return retval;
}

int contains_pre_key(uint32_t pre_key_id, void *user_data)
{
    int retval = 0;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("contains_pre_key?"), 0);
    
    return retval;
}

int remove_pre_key(uint32_t pre_key_id, void *user_data)
{
    int retval = 0;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("remove_pre_key"), 0);
    
    return retval;
}
