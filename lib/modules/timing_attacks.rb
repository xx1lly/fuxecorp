require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class TimingAttacks
  def self.test_timing_attack(url, parameter, correct_value, wrong_value, iterations = 100)
    correct_times = []
    wrong_times = []
    
    iterations.times do
      begin
        start = Time.now
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{correct_value}" : "#{url}?#{parameter}=#{correct_value}"
        Network.http_request(test_url)
        correct_times << (Time.now - start)
      rescue => e
      end
    end
    
    iterations.times do
      begin
        start = Time.now
        test_url = url.include?('?') ? "#{url}&#{parameter}=#{wrong_value}" : "#{url}?#{parameter}=#{wrong_value}"
        Network.http_request(test_url)
        wrong_times << (Time.now - start)
      rescue => e
      end
    end
    
    avg_correct = correct_times.sum / correct_times.length
    avg_wrong = wrong_times.sum / wrong_times.length
    diff = (avg_correct - avg_wrong).abs
    
    puts Colorize.yellow("Average correct: #{avg_correct}s")
    puts Colorize.yellow("Average wrong: #{avg_wrong}s")
    puts Colorize.yellow("Difference: #{diff}s")
    
    if diff > 0.1
      puts Colorize.red("Timing attack possible")
      return { vulnerable: true, difference: diff }
    else
      puts Colorize.green("Timing attack not feasible")
      return { vulnerable: false, difference: diff }
    end
  end

  def self.test_username_enumeration(url, usernames)
    results = {}
    
    usernames.each do |username|
      times = []
      10.times do
        begin
          start = Time.now
          test_url = url.include?('?') ? "#{url}&username=#{username}" : "#{url}?username=#{username}"
          Network.http_request(test_url)
          times << (Time.now - start)
        rescue => e
        end
      end
      
      avg_time = times.sum / times.length
      results[username] = avg_time
      puts "#{username}: #{avg_time}s"
    end
    
    sorted = results.sort_by { |k, v| v }.reverse
    if sorted.first[1] - sorted.last[1] > 0.1
      puts Colorize.red("Username enumeration possible")
      puts Colorize.yellow("Slowest: #{sorted.first[0]} (#{sorted.first[1]}s)")
    end
    
    results
  end
end

