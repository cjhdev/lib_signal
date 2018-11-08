#include <ruby.h>
#include "signal_protocol.h"

int store_sender_key(const signal_protocol_sender_key_name *sender_key_name, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data)
{
    int retval = -1;

    rb_funcall((VALUE)user_data, rb_intern("store_sender_key"), 0);
    
    return retval;
}

int load_sender_key(signal_buffer **record, signal_buffer **user_record, const signal_protocol_sender_key_name *sender_key_name, void *user_data)
{
    int retval = -1;
    
    rb_funcall((VALUE)user_data, rb_intern("load_sender_key"), 0);
    
    return retval;
}
