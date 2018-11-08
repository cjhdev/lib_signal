#include <ruby.h>

void global_lock(void *user_data)
{
    rb_funcall(rb_iv_get((VALUE)user_data, "@global_lock"), rb_intern("lock"), 0);
}

void global_unlock(void *user_data)
{
    rb_funcall(rb_iv_get((VALUE)user_data, "@global_lock"), rb_intern("unlock"), 0);
}
