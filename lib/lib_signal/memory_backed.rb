module LibSignal

  class MemoryBacked < Persistence
    
    attr_reader :name
    
    def initialize(name)
      @name = name
      @identity_key = nil
      @registration_id = nil     
      @sessions = {}      
      @pre_keys = {}
      @signed_pre_keys = {} 
      @sender_keys = {}
    end
    
    def install(params)
      if not installed?
        @identity_key = params[:identity_key]
        @registration_id = params[:registration_id]
        @pre_keys = params[:pre_keys]
        @signed_pre_keys = params[:signed_pre_key]
      end    
    end
    
    def installed?
      @identity_key and @registration_id
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

    def post_sender_key(group_id, name, id, record, user_record)
      data = {
        :id => id,
        :name => name,
        :group_id => group_id,
        :record => record,
        :user_record => user_record
      }
      @sender_keys["#{group_id}#{name}#{id}"] = data      
      true      
    end
    
    def get_sender_key(name, id, group_id)
      @sender_keys["#{group_id}#{name}#{id}"]      
    end
    
  end

end
