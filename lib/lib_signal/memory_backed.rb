require_relative 'persistence'

module LibSignal

  class MemoryBacked < Persistence
    
    def initialize      
      @identity_key = nil
      @registration_id = nil     
      @sessions = {}      
      @pre_keys = {}
      @signed_pre_keys = {} 
      @sender_keys = {}
    end
    
    def get_session(name, id)
      if s = @sessions[name]
        s[id]
      else
        nil
      end         
    end
    
    def get_session_ids(name)
      if @sessions[name]      
        @sessions.keys
      else
        []
      end
    end
    
    def post_session(name, id, record, user_record)
      data = {
        :id => id,
        :record => record,
        :user_record => user_record
      }      
      if s = @sessions[name]
        s[id] = data
      else
        @sessions[name] = {
          id => data
        }
      end
      true      
    end
    
    def session_exists?(name, id)
      @sessions[name] and @sessions[name][id]        
    end
    
    def delete_session(name, id)
      if @sessions[name]
        @sessions[name].delete(id)
      end
      true
    end
    
    def delete_all_sessions(name)
      @sessions.delete(name)
      true
    end
    
    def get_identity_key_pair
      @identity_key    
    end
    
    def get_registration_id
      @registration_id      
    end
    
    def post_identity(name, id, public_key)
      data = {
        :id => id,
        :key => public_key
      }      
      if r = @remotes[name]
        r[id] = data        
      else
        @remotes[name] = {
          id => data
        }      
      end
      true
    end
    
    def identity_is_trusted?(name, id)
      true
    end

    def get_signed_pre_key(id)
      @signed_pre_keys[id]
    end
    
    def post_signed_pre_key(id, record)
      @signed_pre_keys[id] = {
        :id => id,
        :key => record
      }
      true
    end
    
    def signed_pre_key_exists?(id)
      ( @signed_pre_keys[id] ? true : false )    
    end
    
    def delete_signed_pre_key(id)
      @signed_pre_keys.delete(id)
      true
    end
    
    def get_pre_key(id)
      @pre_keys[id]    
    end
    
    def post_pre_key(id, record)
      @pre_keys[id] = {
        :id => id,
        :key => record
      }
      true
    end
    
    def pre_key_exists?(id)
      ( @pre_keys[id] ? true : false )
    end
    
    def delete_pre_key(id)
      @pre_keys.delete(id)
      true
    end

    def post_sender_key(name, id, group_id, record, user_record)
      data = {
        :id => id,
        :group_id => group_id,
        :record => record,
        :user_record => user_record
      }
      key = "#{name}#{id}#{group_id}"      
      @sender_keys[key] = data      
      true      
    end
    
    def get_sender_key(name, id, group_id)
      @sender_keys["#{name}#{id}#{group_id}"]      
    end
  end

end
