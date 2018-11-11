class LibSignal

  class Address 

    attr_reader :name, :device_id

    def initialize(name, device_id)
      
      raise TypeError unless name.kind_of? String
      raise TypeError unless device_id.kind_of? Integer
      raise RangeError unless (0..(2**31-1)).include? device_id
      
      @name = name
      @device_id = device_id
      
    end

  end
  
end
