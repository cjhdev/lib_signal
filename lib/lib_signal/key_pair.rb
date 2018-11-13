module LibSignal
  class IdentityKey
    attr_reader :pub, :priv, :record
    def initialize(**attr)
      @pub = attr[:pub]
      @priv = attr[:priv]
      @record = attr[:record]
    end
  end
end
