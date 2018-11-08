require_relative 'ext_lib_signal'
require_relative 'persistence'

module LibSignal

  class ExtClient

    include Persistence
  
    def log(level, msg)
      puts "#{level}: #{msg}"
    end
  
  end

end
