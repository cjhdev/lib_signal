module LibSignal

  class Persistence
  
    # @param name [String]
    # @param device_id [Integer]
    # @return [Hash]
    def get_session(name, device_id)
      raise NotImplementedError
    end
    
    # @param name [String]
    # @return [Array<Integer>] 
    def get_session_devices(name)
      raise NotImplementedError
    end
    
    # @param name [String]
    # @param device_id [Integer]
    # @param record [String]
    # @param user_record [String] optional
    # @return [self]
    def put_session(name, device_id, record, user_record=nil)
      raise NotImplementedError
    end
    
    # @param name [String]
    # @param device_id [Integer]
    # @return [true,false]
    def session_exists?(name, device_id)
      raise NotImplementedError
    end
    
    # @param name [String]
    # @param device_id [Integer]
    # @return [self]
    def delete_session(name, device_id)
      raise NotImplementedError
    end
    
    # @param name [String]
    # @return [self]
    def delete_all_sessions(name)
      raise NotImplementedError
    end
    
    def get_identity_key_pair
      raise NotImplementedError
    end
    
    def get_registration_id
      raise NotImplementedError
    end
    
    def get_self
      raise NotImplementedError
    end
    
    def save_identity(name, id, public_key)
      raise NotImplementedError
    end
    
    def identity_is_trusted?(name, id)
      raise NotImplementedError
    end

    def get_signed_pre_key(id)
      raise NotImplementedError
    end
    
    def put_signed_pre_key(id, record)
      raise NotImplementedError
    end
    
    def signed_pre_key_exists?(id)
      raise NotImplementedError
    end
    
    def delete_signed_pre_key(id)
      raise NotImplementedError
    end
    
    def get_pre_key(id)
      raise NotImplementedError
    end
    
    def put_pre_key(id, record)
      raise NotImplementedError
    end
    
    def pre_key_exists?(id)
      raise NotImplementedError
    end
    
    def delete_pre_key(id)
      raise NotImplementedError
    end

    def put_sender_key(name, id, group_id, record, user_record)
      raise NotImplementedError
    end
    
    def get_sender_key(name, id, group_id)
      raise NotImplementedError
    end
    
  end

end
