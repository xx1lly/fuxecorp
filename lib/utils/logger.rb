require 'fileutils'
require_relative 'colorize'

class Logger
  def initialize(log_dir = 'logs')
    @log_dir = log_dir
    FileUtils.mkdir_p(@log_dir)
    @log_file = File.join(@log_dir, "pentest_#{Time.now.strftime('%Y%m%d_%H%M%S')}.log")
  end

  def log(level, message, data = nil)
    timestamp = Time.now.strftime('%Y-%m-%d %H:%M:%S')
    log_entry = "[#{timestamp}] [#{level}] #{message}"
    log_entry += " | Data: #{data.inspect}" if data
    
    File.open(@log_file, 'a') do |f|
      f.puts(log_entry)
    end
    
    case level
    when 'ERROR'
      puts Colorize.red(log_entry)
    when 'WARN'
      puts Colorize.yellow(log_entry)
    when 'INFO'
      puts Colorize.cyan(log_entry)
    when 'SUCCESS'
      puts Colorize.green(log_entry)
    else
      puts log_entry
    end
  end

  def error(message, data = nil)
    log('ERROR', message, data)
  end

  def warn(message, data = nil)
    log('WARN', message, data)
  end

  def info(message, data = nil)
    log('INFO', message, data)
  end

  def success(message, data = nil)
    log('SUCCESS', message, data)
  end
end

