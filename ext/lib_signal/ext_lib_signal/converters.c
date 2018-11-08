#include "converters.h"

VALUE buffer_to_rstring(const signal_buffer *buffer)
{
    return rb_str_new((char *)signal_buffer_const_data(buffer), signal_buffer_len(buffer));
}

VALUE rstring_to_buffer(VALUE str)
{
    return signal_buffer_create((uint8_t *)RSTRING_PTR(str), (size_t)RSTRING_LEN(str));
}

#if 0
VALUE blist_to_array(signal_buffer_list *list)
{
    VALUE retval = rb_ary_new();
    unsigned int size = signal_buffer_list_size(list);
    unsigned int i;
    
    for(i=0U; i < size; i++){
        
        assert(signal_buffer_list_at(list, i) != NULL);
        
        rb_ary_push(retval, buffer_to_rstring(signal_buffer_list_at(list, i)));        
    }
    
    return retval;
}
#endif
