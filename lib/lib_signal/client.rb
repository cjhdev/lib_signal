module LibSignal

  class Client
    
    # params: 
    #   :data inject persistence
    #   :max_pre_keys
    #
    #
    #
    def initialize(address, **opts)
      
      @data = opts[:data]||MemoryBacked.new(address)
      @ext = ExtClient.new(@data)
      
      # if this device is new we need to install some starting values
      if not @data.installed?
        
        @data.install(
          :identity_key => @ext.generate_identity_key_pair,
          :registration_id => @ext.generate_registration_id,
          :pre_keys => @ext.generate_signed_pre_key,
          :signed_pre_key => @ext.generate_signed_pre_key
        )
        
      end
      
    end

    # provides a single pre_key
    def peer_bundle
    end
    
    # provides a set of pre_keys
    def registration_bundle
    end
    
  end
  
end

