module LibSignal

  class PreKey
    
    attr_reader :id, :priv, :pub, :record
    
    def initialize(**args)    
      @id = args[:id]
      @priv = args[:priv]
      @pub = args[:pub]
      @record = args[:record]
    end
    
    def to_store
      {
        :id => id,
        :record => record
      }
    end
  
  end

end
