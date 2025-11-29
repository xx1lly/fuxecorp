require 'digest'
require 'openssl'
require 'json'
require_relative '../utils/colorize'

class PasswordCracking
  COMMON_PASSWORDS = %w[
    password 123456 123456789 12345678 12345 1234567 password123
    admin root toor passw0rd welcome 123123 qwerty abc123
    monkey 1234567890 letmein trustno1 dragon baseball iloveyou
    master sunshine ashley bailey shadow 1234 superman qwerty123
    michael football 654321 jesus welcome1 login admin123
  ]

  def self.crack_hash(hash, wordlist = nil)
    words = wordlist ? File.readlines(wordlist).map(&:chomp) : COMMON_PASSWORDS
    hash_type = identify_hash_type(hash)
    
    words.each do |word|
      computed = compute_hash(word, hash_type)
      if computed == hash
        puts Colorize.green("Password found: #{word}")
        return word
      end
    end
    
    nil
  end

  def self.identify_hash_type(hash)
    case hash.length
    when 32 then :md5
    when 40 then :sha1
    when 64 then :sha256
    when 128 then :sha512
    when 34 then hash.start_with?('$2') ? :bcrypt : :unknown
    else :unknown
    end
  end

  def self.compute_hash(text, type)
    case type
    when :md5 then Digest::MD5.hexdigest(text)
    when :sha1 then Digest::SHA1.hexdigest(text)
    when :sha256 then Digest::SHA256.hexdigest(text)
    when :sha512 then Digest::SHA512.hexdigest(text)
    when :bcrypt then OpenSSL::Digest::SHA256.hexdigest(text)
    else text
    end
  end

  def self.generate_rainbow_table(wordlist, output_file)
    words = File.readlines(wordlist).map(&:chomp)
    table = {}
    
    words.each do |word|
      table[Digest::MD5.hexdigest(word)] = word
      table[Digest::SHA1.hexdigest(word)] = word
      table[Digest::SHA256.hexdigest(word)] = word
    end
    
    File.write(output_file, table.to_json)
    puts Colorize.green("Rainbow table generated: #{output_file}")
    table
  end

  def self.bruteforce_mask(mask, charset = nil)
    chars = charset || ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a
    positions = mask.chars.map.with_index { |c, i| c == '?' ? i : nil }.compact
    
    return [mask] if positions.empty?
    
    results = []
    total = chars.length ** positions.length
    
    (0...total).each do |i|
      result = mask.dup
      temp = i
      positions.each do |pos|
        result[pos] = chars[temp % chars.length]
        temp /= chars.length
      end
      results << result
    end
    
    results
  end

  def self.dictionary_attack(target_hash, dictionary, rules = [])
    words = File.readlines(dictionary).map(&:chomp)
    hash_type = identify_hash_type(target_hash)
    
    words.each do |word|
      variants = apply_rules(word, rules)
      variants.each do |variant|
        computed = compute_hash(variant, hash_type)
        if computed == target_hash
          puts Colorize.green("Password found: #{variant}")
          return variant
        end
      end
    end
    
    nil
  end

  def self.apply_rules(word, rules)
    variants = [word]
    
    rules.each do |rule|
      case rule
      when :uppercase
        variants << word.upcase
      when :lowercase
        variants << word.downcase
      when :capitalize
        variants << word.capitalize
      when :append_numbers
        (0..999).each { |i| variants << "#{word}#{i}" }
      when :prepend_numbers
        (0..999).each { |i| variants << "#{i}#{word}" }
      when :leet
        variants << word.tr('aeio', '4310')
      when :reverse
        variants << word.reverse
      when :duplicate
        variants << word * 2
      end
    end
    
    variants.uniq
  end
end

