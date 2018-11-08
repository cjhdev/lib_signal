require 'mkmf'

SRC_ROOT = File.join(__dir__, "libsignal-protocol-c", "src")

vpaths = %w[
  .
  protobuf-c
  curve25519
  curve25519/ed25519
  curve25519/ed25519/additions
  curve25519/ed25519/additions/generalized
  curve25519/ed25519/nacl_sha512
  curve25519/ed25519/tests  
]

includes = %w[
  .
  curve25519/ed25519/nacl_includes
  curve25519/ed25519/additions
  curve25519/ed25519/additions/generalized
  curve25519/ed25519/sha512
  curve25519/ed25519
  curve25519
]

$srcs = Dir[File.join(__dir__, "*.c")]

vpaths.each do |path|

  $VPATH << File.join(SRC_ROOT, path)
  $srcs += Dir[File.join(SRC_ROOT, path, "*.c")]

end

includes.each do |dir| 
  $INCFLAGS << " -I#{File.join(SRC_ROOT, dir)}"    
end
    
create_makefile('lib_signal/ext_lib_signal')

