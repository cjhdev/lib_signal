#ifndef CONVERTERS_H
#define CONVERTERS_H

#include "signal_protocol.h"
#include <ruby.h>


VALUE buffer_to_rstring(const signal_buffer *buffer);
VALUE rstring_to_buffer(VALUE str);


#endif
