class Colorize
  class << self
    def red(str); "\e[31m#{str}\e[0m"; end
    def green(str); "\e[32m#{str}\e[0m"; end
    def yellow(str); "\e[33m#{str}\e[0m"; end
    def blue(str); "\e[34m#{str}\e[0m"; end
    def magenta(str); "\e[35m#{str}\e[0m"; end
    def cyan(str); "\e[36m#{str}\e[0m"; end
    def bold(str); "\e[1m#{str}\e[0m"; end
  end
end

