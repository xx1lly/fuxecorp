require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class CSRF
  def self.test_csrf_protection(url, method = :post)
    begin
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
      
      req = case method
      when :post then Net::HTTP::Post.new(uri.path)
      when :put then Net::HTTP::Put.new(uri.path)
      when :delete then Net::HTTP::Delete.new(uri.path)
      else Net::HTTP::Post.new(uri.path)
      end
      
      req.set_form_data('test' => 'value')
      
      res = http.request(req)
      
      body = res.body.downcase
      headers = res.to_hash
      
      has_token = body.include?('csrf') || body.include?('token') || body.include?('_token') || body.include?('authenticity_token')
      has_header = headers['x-csrf-token'] || headers['csrf-token'] || headers['x-csrf']
      has_cookie = res['Set-Cookie']&.include?('csrf') || res['Set-Cookie']&.include?('token')
      
      if has_token || has_header || has_cookie
        puts Colorize.green("CSRF protection detected")
        return { protected: true, token_found: has_token, header_found: !!has_header, cookie_found: has_cookie }
      else
        puts Colorize.red("No CSRF protection detected")
        return { protected: false }
      end
    rescue => e
      return { protected: false, error: e.message }
    end
  end

  def self.generate_csrf_poc(url, action, parameters = {})
    poc = <<~HTML
      <html>
      <body>
        <h1>CSRF PoC</h1>
        <form action="#{url}#{action}" method="POST" id="csrf-form">
    HTML
    
    parameters.each do |key, value|
      poc += "      <input type=\"hidden\" name=\"#{key}\" value=\"#{value}\">\n"
    end
    
    poc += <<~HTML
        </form>
        <script>
          document.getElementById('csrf-form').submit();
        </script>
      </body>
      </html>
    HTML
    
    filename = "csrf_poc_#{Time.now.to_i}.html"
    File.write(filename, poc)
    puts Colorize.green("CSRF PoC saved: #{filename}")
    filename
  end

  def self.test_same_site_cookie(url)
    begin
      response = Network.http_request(url)
      
      if response['Set-Cookie']
        cookies = response.get_fields('Set-Cookie')
        
        cookies.each do |cookie|
          if cookie.include?('SameSite=None') || cookie.include?('SameSite=Lax') || cookie.include?('SameSite=Strict')
            puts Colorize.green("SameSite cookie attribute found: #{cookie.match(/SameSite=([^;]+)/)[1]}")
            return { same_site: cookie.match(/SameSite=([^;]+)/)[1] }
          end
        end
        
        puts Colorize.red("No SameSite attribute found")
        return { same_site: nil, vulnerable: true }
      end
    rescue => e
      return { error: e.message }
    end
    
    { same_site: nil }
  end

  def self.test_referer_validation(url)
    begin
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
      
      req = Net::HTTP::Post.new(uri.path)
      req.set_form_data('test' => 'value')
      req['Referer'] = 'http://evil.com'
      
      res = http.request(req)
      
      if res.code.to_i == 200 || res.code.to_i == 302
        puts Colorize.red("Referer validation not enforced")
        return { validated: false, vulnerable: true }
      else
        puts Colorize.green("Referer validation enforced")
        return { validated: true, vulnerable: false }
      end
    rescue => e
      return { error: e.message }
    end
  end
end

