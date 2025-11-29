require 'uri'
require_relative '../utils/network'
require_relative '../utils/colorize'

class SessionManagement
  def self.test_session_fixation(url)
    response1 = Network.http_request(url)
    return nil unless response1
    
    session1 = extract_session(response1)
    
    response2 = Network.http_request(url)
    return nil unless response2
    
    session2 = extract_session(response2)
    
    {
      session1: session1,
      session2: session2,
      vulnerable: session1 == session2 && !session1.nil?
    }
  end

  def self.test_session_timeout(url, delay = 3600)
    response1 = Network.http_request(url)
    return nil unless response1
    
    session1 = extract_session(response1)
    
    sleep(delay)
    
    response2 = Network.http_request(url, :get, { 'Cookie' => "session=#{session1}" })
    return nil unless response2
    
    {
      session1: session1,
      session2: extract_session(response2),
      expired: response2.code == "401" || response2.code == "403"
    }
  end

  def self.test_session_hijacking(url, session_id)
    response = Network.http_request(url, :get, { 'Cookie' => "session=#{session_id}" })
    return nil unless response
    
    {
      status: response.code,
      body_length: response.body.length,
      authenticated: response.body.include?("logout") || response.body.include?("profile")
    }
  end

  def self.test_concurrent_sessions(url, username, password)
    sessions = []
    
    5.times do
      response = Network.http_request("#{url}/login", :post, { 'Content-Type' => 'application/x-www-form-urlencoded' }, "username=#{username}&password=#{password}")
      next unless response
      
      session = extract_session(response)
      sessions << session if session
    end
    
    {
      sessions: sessions,
      concurrent_allowed: sessions.length > 1
    }
  end

  def self.test_session_regeneration(url)
    response1 = Network.http_request(url)
    return nil unless response1
    
    session1 = extract_session(response1)
    
    response2 = Network.http_request("#{url}/login", :post)
    return nil unless response2
    
    session2 = extract_session(response2)
    
    {
      session1: session1,
      session2: session2,
      regenerated: session1 != session2
    }
  end

  def self.extract_session(response)
    cookies = response.get_fields('Set-Cookie')
    return nil unless cookies
    
    cookies.each do |cookie|
      if cookie.include?('session') || cookie.include?('Session') || cookie.include?('SESSION')
        match = cookie.match(/(?:session|Session|SESSION)=([^;]+)/i)
        return match[1] if match
      end
    end
    
    nil
  end

  def self.test_csrf(url)
    response = Network.http_request(url)
    return nil unless response
    
    body = response.body
    csrf_token = extract_csrf_token(body)
    
    {
      csrf_token: csrf_token,
      csrf_protected: !csrf_token.nil?,
      token_location: find_token_location(body, csrf_token)
    }
  end

  def self.extract_csrf_token(body)
    patterns = [
      /<input[^>]*name=["']csrf[_-]?token["'][^>]*value=["']([^"']+)["']/i,
      /<input[^>]*name=["']_token["'][^>]*value=["']([^"']+)["']/i,
      /<input[^>]*name=["']authenticity[_-]?token["'][^>]*value=["']([^"']+)["']/i,
      /<meta[^>]*name=["']csrf[_-]?token["'][^>]*content=["']([^"']+)["']/i,
      /csrf[_-]?token["']?\s*[:=]\s*["']([^"']+)["']/i
    ]
    
    patterns.each do |pattern|
      match = body.match(pattern)
      return match[1] if match
    end
    
    nil
  end

  def self.find_token_location(body, token)
    return nil unless token
    
    if body.include?("csrf")
      "form"
    elsif body.include?("meta")
      "meta"
    elsif body.include?("header")
      "header"
    else
      "unknown"
    end
  end
end

