module LibSignal
  class KeyPair
    attr_reader :pub, :priv
    def initialize(**attr)
      @pub = attr[:pub]
      @priv = attr[:priv]
    end
  end
end
