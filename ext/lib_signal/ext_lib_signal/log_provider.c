#include <ruby.h>

void global_log(int level, const char *message, size_t len, void *user_data)
{
    rb_funcall((VALUE)user_data, rb_intern("log"), 2, INT2NUM(level), rb_str_new(message, len));
}
