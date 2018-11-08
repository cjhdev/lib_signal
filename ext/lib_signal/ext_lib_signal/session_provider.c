#include <ruby.h>
#include "signal_protocol.h"

int my_get_session(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data)
{
    int retval = 0;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("load_session"), 
        2, 
        rb_str_new((char *)address->name, address->name_len), 
        INT2NUM(address->device_id)
    );

    if(result != Qnil){
    
        *record = rstring_to_buffer(rb_ary_entry(result, 0));
        *user_record = (rb_ary_entry(result, 1) != Qnil) ? rstring_to_buffer(rb_ary_entry(result, 1)) : NULL;
    
        retval = 1;
    }
    
    return retval;
}

int my_get_all_sessions(signal_int_list **sessions, const char *name, size_t name_len, void *user_data)
{
    int retval = 0;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("get_sub_device_sessions"), 0);

    if(result != Qnil){
    
        retval = 1;
    }
    
    return retval;    
}

int my_put_session(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data)
{
    int retval = -1;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("store_session"), 
        4,
        rb_str_new((char *)address->name, address->name_len), 
        INT2NUM(address->device_id),
        rb_str_new((char *)record, record_len),
        rb_str_new((char *)user_record, user_record_len)
    );
    
    return retval;
}

int my_session_exists(const signal_protocol_address *address, void *user_data)
{
    int retval = 0;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("contains_session?"), 0);
    
    return retval;
}

int my_delete_session(const signal_protocol_address *address, void *user_data)
{
    int retval = 1;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("delete_session"), 0);
    
    return retval;
}

int my_delete_all_sessions(const char *name, size_t name_len, void *user_data)
{
    int retval = 0;
    
    VALUE result = rb_funcall((VALUE)user_data, rb_intern("delete_all_sessions"), 0);
    
    return retval;
}

