module LibSignal

  class ExtClient

    attr_reader :data

    def log(level, msg)
      puts "#{level}: #{msg}"
    end
    
  end

end
