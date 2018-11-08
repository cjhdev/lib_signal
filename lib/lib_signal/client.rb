require_relative 'ext_client'
require_relative 'persistence'

module LibSignal

  class Client
    
    attr_reader :name

    def initialize(name, **opts)
      
      @name = name
      
      @ext = ExtClient.new
      
      identity_key_pair = @ext.generate_identity_key_pair      
      
      registration_id = @ext.generate_registration_id
      
      signed_pre_key = @ext.generate_signed_pre_key
      
    end
    
    # @return [Integer]
    def registration_id
      @ext.get_registration_id
    end
    
    # Add or update a remote client
    #
    def add_remote
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

