require 'securerandom'
require_relative '../utils/colorize'

class InsecureRandom
  def self.test_weak_random(url, parameter = 'token')
    begin
      tokens = []
      100.times do
        test_url = url.include?('?') ? "#{url}&#{parameter}=test" : "#{url}?#{parameter}=test"
        response = Network.http_request(test_url)
        
        if response
          token_match = response.body.match(/#{parameter}=([a-zA-Z0-9]+)/)
          tokens << token_match[1] if token_match
        end
      end
      
      if tokens.length > 10
        unique = tokens.uniq.length
        if unique < tokens.length * 0.1
          puts Colorize.red("Weak random detected - many duplicates")
          return { vulnerable: true, duplicates: tokens.length - unique }
        end
        
        patterns = analyze_patterns(tokens)
        if patterns[:sequential] || patterns[:predictable]
          puts Colorize.red("Predictable random detected")
          return { vulnerable: true, patterns: patterns }
        end
      end
    rescue => e
    end
    
    { vulnerable: false }
  end

  def self.analyze_patterns(tokens)
    sequential = false
    predictable = false
    
    if tokens.length > 1
      tokens.each_with_index do |token, i|
        next if i == 0
        
        prev = tokens[i - 1]
        
        if token.to_i > 0 && prev.to_i > 0
          if (token.to_i - prev.to_i).abs == 1
            sequential = true
          end
        end
        
        if token.length == prev.length
          diff = 0
          token.chars.each_with_index do |char, j|
            diff += 1 if char != prev[j]
          end
          if diff <= 2
            predictable = true
          end
        end
      end
    end
    
    { sequential: sequential, predictable: predictable }
  end

  def self.test_session_id_entropy(url)
    begin
      session_ids = []
      50.times do
        response = Network.http_request(url)
        if response['Set-Cookie']
          session_match = response['Set-Cookie'].match(/([^=]+)=([^;]+)/)
          session_ids << session_match[2] if session_match
        end
      end
      
      if session_ids.length > 10
        unique = session_ids.uniq.length
        entropy = calculate_entropy(session_ids)
        
        puts Colorize.yellow("Unique session IDs: #{unique}/#{session_ids.length}")
        puts Colorize.yellow("Entropy: #{entropy}")
        
        if entropy < 4.0
          puts Colorize.red("Low entropy - weak random")
          return { vulnerable: true, entropy: entropy }
        end
      end
    rescue => e
    end
    
    { vulnerable: false }
  end

  def self.calculate_entropy(values)
    return 0 if values.empty?
    
    freq = Hash.new(0)
    values.each { |v| freq[v] += 1 }
    
    entropy = 0.0
    total = values.length.to_f
    
    freq.each_value do |count|
      probability = count / total
      entropy -= probability * Math.log2(probability) if probability > 0
    end
    
    entropy
  end
end

