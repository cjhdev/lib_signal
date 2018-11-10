module LibSignal

  class Client
    
    def initialize(name, **opts)
      
      @data = opts[:data]||MemoryBacked.new(name)
      @ext = ExtClient.new(@data)
      
      if not @data.installed?
        
        @data.install(
          :identity_key => @ext.generate_identity_key_pair,
          :registration_id => @ext.generate_registration_id,
          :pre_keys => @ext.generate_signed_pre_key,
          :signed_pre_key => @ext.generate_signed_pre_key
        )
        
      end
      
    end
    
    def name
      @data.name
    end
    
    # @return [Integer]
    def registration_id
      @data.get_registration_id
    end
    
    # Add or update a remote client
    #
    def add_session(name, id, pre_key)
      
    end
    
    # List remotes
    #
    # @return [Array]
    def remotes
    end
    
    def remove_remote
    end
    
    # Encode a message for named recipient
    #
    # @param client_name [String]
    # @param msg [String] plaintext to encode
    #
    # @return [String] encoded message
    #
    # @raises [NoSessionError] no session for this client
    #
    def encode(client_name, msg)
    end
    
    # Decode a message from named recipient
    #
    # @param client_name [String]
    # @param msg [String] encoded message
    #
    # @return [String] plaintext
    #
    # @raises [DecodeError]
    def decode(client_name, msg)
    end
    
  end
  
end

