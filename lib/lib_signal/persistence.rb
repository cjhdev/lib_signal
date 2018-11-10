module LibSignal

  class Persistence
  
    # load specific session
    def get_session(name, id)
      raise NotImplementedError
    end
    
    # load all sessions
    def get_all_sessions(name)
      raise NotImplementedError
    end
    
    # store a session
    def put_session(name, id, record, user_record)
      raise NotImplementedError
    end
    
    # does this session exist?
    def session_exists?(name, id)
      raise NotImplementedError
    end
    
    # delete a session
    def delete_session(name, id)
      raise NotImplementedError
    end
    
    # delete all sessions
    def delete_all_sessions(name)
      raise NotImplementedError
    end
    
    def get_identity_key_pair
      raise NotImplementedError
    end
    
    def get_registration_id
      raise NotImplementedError
    end
    
    # @return [Hash]
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
