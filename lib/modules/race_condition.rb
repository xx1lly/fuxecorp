require 'uri'
require 'thread'
require_relative '../utils/network'
require_relative '../utils/colorize'

class RaceCondition
  def self.test_time_of_check_time_of_use(url, requests = 100)
    results = []
    threads = []
    
    requests.times do |i|
      threads << Thread.new do
        begin
          response = Network.http_request(url)
          if response
            results << {
              request: i + 1,
              status: response.code,
              time: Time.now
            }
          end
        rescue
        end
      end
    end
    
    threads.each(&:join)
    
    {
      total_requests: results.length,
      unique_statuses: results.map { |r| r[:status] }.uniq,
      results: results
    }
  end

  def self.test_parallel_requests(url, count = 50)
    results = []
    threads = []
    
    count.times do |i|
      threads << Thread.new do
        begin
          start_time = Time.now
          response = Network.http_request(url)
          elapsed = Time.now - start_time
          
          results << {
            request: i + 1,
            status: response&.code,
            elapsed: elapsed
          }
        rescue
        end
      end
    end
    
    threads.each(&:join)
    
    {
      total: results.length,
      avg_time: results.map { |r| r[:elapsed] }.sum / results.length,
      results: results
    }
  end

  def self.test_concurrent_modification(url, param, value, requests = 100)
    results = []
    threads = []
    
    requests.times do |i|
      threads << Thread.new do
        begin
          test_url = url.include?("?") ? "#{url}&#{param}=#{value}#{i}" : "#{url}?#{param}=#{value}#{i}"
          response = Network.http_request(test_url, :post)
          
          results << {
            request: i + 1,
            status: response&.code,
            value: "#{value}#{i}"
          }
        rescue
        end
      end
    end
    
    threads.each(&:join)
    
    {
      total: results.length,
      unique_statuses: results.map { |r| r[:status] }.uniq,
      results: results
    }
  end

  def self.test_idempotency(url, method = :post, requests = 10)
    results = []
    threads = []
    
    requests.times do |i|
      threads << Thread.new do
        begin
          response = Network.http_request(url, method)
          results << {
            request: i + 1,
            status: response&.code,
            time: Time.now
          }
        rescue
        end
      end
    end
    
    threads.each(&:join)
    
    statuses = results.map { |r| r[:status] }.uniq
    {
      total: results.length,
      idempotent: statuses.length == 1,
      statuses: statuses,
      results: results
    }
  end
end

