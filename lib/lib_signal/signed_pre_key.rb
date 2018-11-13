module LibSignal

  class SignedPreKey
  
    attr_reader :pub, :priv, :timestamp, :signature, :id, :record
  
    def initialize(**args)
      @pub = args[:pub]
      @priv = args[:priv]
      @timestamp = args[:timestamp]
      @signature = args[:signature]
      @id = args[:id]
      @record = args[:record]
    end
  
  end

end
