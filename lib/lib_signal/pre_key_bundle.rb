module LibSignal

  class PreKeyBundle 
    
    attr_reader :name
    attr_reader :registration_id
    attr_reader :device_id
    attr_reader :pre_key_id
    attr_reader :pre_key_pub
    attr_reader :signed_pre_key_id
    attr_reader :signed_pre_key_pub
    attr_reader :signed_pre_key_sig
    attr_reader :identity_key_pub
  
    def initialize(**args)

      check = Proc.new do |key, type, range=nil|
        raise ArgumentError.new "missing :#{key}" unless args.has_key? key
        raise TypeError.new ":#{key} must be #{type.name}" unless args[key].kind_of? type
        raise RangeError unless range.nil? or range.include? args[key]
      end

      check.call(:name, String)
      check.call(:registration_id, Integer)
      check.call(:device_id, Integer)
      check.call(:pre_key_id, Integer)
      check.call(:pre_key_pub, String)
      check.call(:signed_pre_key_id, Integer)
      check.call(:signed_pre_key_pub, String)
      check.call(:signed_pre_key_sig, String)
      check.call(:identity_key_pub, String)

      @name = args[:name]
      @device_id = args[:device_id]
      @registration_id = args[:registration_id]
      @pre_key_id = args[:pre_key_id]
      @pre_key_pub = args[:pre_key_pub]
      @signed_pre_key_id = args[:signed_pre_key_id]
      @signed_pre_key_pub = args[:signed_pre_key_pub]
      @signed_pre_key_sig = args[:signed_pre_key_sig]
      @identity_key_pub = args[:identity_key_pub]
      
      
    end
  
  end
    
end
