require 'minitest/autorun'
require 'lib_signal'

class TestExtClient < Minitest::Test

  include LibSignal
  
  def setup
    @client = ExtClient.new
  end

  def test_generate_identity_key_pair
    assert_kind_of String, @client.generate_identity_key_pair
  end
  
  def test_generate_registration_id
    assert_kind_of Integer, @client.generate_registration_id(false)
  end
  
  def test_generate_registration_id_extended
    assert_kind_of Integer, @client.generate_registration_id(true)
  end
  
  def test_generate_pre_keys
  
    keys = @client.generate_pre_keys(0,10)
    
    assert_kind_of Array, keys
    assert_equal 10, keys.size
  
  end
  
  def test_generate_pre_keys_zero
  
    keys = @client.generate_pre_keys(0,0)
    
    assert_kind_of Array, keys
    assert_equal 0, keys.size
  
  end
  
  def test_generate_signed_pre_key
    assert_kind_of String, @client.generate_signed_pre_key( @client.generate_identity_key_pair, 0 )
  end
  
end
