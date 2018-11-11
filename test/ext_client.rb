require 'minitest/autorun'
require 'lib_signal'

class TestExtClient < Minitest::Test

  include LibSignal
  
  def setup
    @client = ExtClient.new(MemoryBacked.new("test"))
  end
  
  def test_generate_identity_key_pair
    
    result = @client.generate_identity_key_pair
    
    assert_kind_of KeyPair, result
    assert_kind_of String, result.pub
    assert_kind_of String, result.priv
    
  end

  def test_generate_registration_id
    
    result = @client.generate_registration_id
    
    assert_kind_of Integer, result
    assert (0 .. (2**32-1)).include? result
    
  end
  
  def test_generate_pre_keys
  
    start_id = rand(0..(2**16-1))
    number = rand(0..100)
  
    keys = @client.generate_pre_keys(start_id,number)
    
    assert_kind_of Array, keys
    assert_equal number, keys.size
  
  end
  
  def test_generate_pre_keys_zero
  
    keys = @client.generate_pre_keys(0,0)
    
    assert_kind_of Array, keys
    assert_equal 0, keys.size
  
  end
  
  def test_generate_signed_pre_key
    @client.generate_signed_pre_key( @client.generate_identity_key_pair, 0 )
  end
  
  def test_clone
    copy = @client.clone
    assert @client != copy
  end
  
  def test_dup
    copy = @client.clone
    assert @client != copy
  end
  
end
