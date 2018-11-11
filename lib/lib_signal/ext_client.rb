module LibSignal

  class ExtClient

    attr_reader :data

    def log(level, msg)
      puts "#{level}: #{msg}"
    end
    
    # @return [Address]
    def address
      @data.address
    end
    
  end

end
