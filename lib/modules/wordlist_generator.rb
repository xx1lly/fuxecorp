require_relative '../utils/colorize'

class WordlistGenerator
  def self.generate_from_base(base, options = {})
    min_length = options[:min_length] || 4
    max_length = options[:max_length] || 20
    include_numbers = options[:include_numbers] != false
    include_special = options[:include_special] != false
    include_uppercase = options[:include_uppercase] != false
    include_lowercase = options[:include_lowercase] != false
    
    wordlist = []
    
    (min_length..max_length).each do |length|
      if include_numbers
        (0..9999).each do |num|
          wordlist << "#{base}#{num}"
          wordlist << "#{num}#{base}"
          wordlist << "#{base}#{num}!" if include_special
          wordlist << "#{num}#{base}!" if include_special
        end
      end
      
      if include_special
        special_chars = %w[! @ # $ % ^ & * ( ) - _ + = [ ] { } | \\ : ; \" ' < > , . ? /]
        special_chars.each do |char|
          wordlist << "#{base}#{char}"
          wordlist << "#{char}#{base}"
          wordlist << "#{base}#{char}#{base}"
        end
      end
      
      if include_uppercase
        wordlist << base.upcase
        wordlist << base.capitalize
        wordlist << base.swapcase
      end
      
      if include_lowercase
        wordlist << base.downcase
      end
    end
    
    wordlist.uniq
  end

  def self.generate_common_passwords(count = 1000)
    common = %w[password 123456 123456789 12345678 12345 1234567 1234567890 qwerty abc123 monkey 1234567 letmein trustno1 dragon baseball iloveyou master sunshine ashley bailey passw0rd shadow 123123 654321 superman qazwsx michael football welcome jesus ninja mustang password1 starwars 1234567890 princess trustno1 daniel computer 000000 tigger charles jasmine michelle 1234567890 secret diamond jordan 1234567890 patrick william thomas hockey hannah michelle 1234567890 shadow monkey 1234567890 master jessica charlie 1234567890 andrew 1234567890 michelle jordan 1234567890 jennifer hunter 1234567890 thomas michelle 1234567890 jessica charlie 1234567890 andrew 1234567890 michelle jordan 1234567890 jennifer hunter 1234567890 thomas]
    
    (0..count).map do |i|
      common[i % common.length] + (i > common.length ? i.to_s : "")
    end
  end

  def self.generate_date_based(base, start_year = 1900, end_year = 2024)
    wordlist = []
    
    (start_year..end_year).each do |year|
      wordlist << "#{base}#{year}"
      wordlist << "#{year}#{base}"
      wordlist << "#{base}#{year}!"
      wordlist << "#{year}#{base}!"
      
      (1..12).each do |month|
        month_str = month.to_s.rjust(2, '0')
        wordlist << "#{base}#{year}#{month_str}"
        wordlist << "#{year}#{month_str}#{base}"
        wordlist << "#{base}#{month_str}#{year}"
        
        (1..31).each do |day|
          day_str = day.to_s.rjust(2, '0')
          wordlist << "#{base}#{year}#{month_str}#{day_str}"
          wordlist << "#{year}#{month_str}#{day_str}#{base}"
          wordlist << "#{base}#{month_str}#{day_str}#{year}"
        end
      end
    end
    
    wordlist.uniq
  end

  def self.generate_permutations(words, max_length = 3)
    wordlist = []
    
    (1..max_length).each do |length|
      words.repeated_permutation(length).each do |perm|
        wordlist << perm.join
        wordlist << perm.join(" ")
        wordlist << perm.join("_")
        wordlist << perm.join("-")
        wordlist << perm.join(".")
      end
    end
    
    wordlist.uniq
  end

  def self.generate_leet_speak(word)
    leet_map = {
      'a' => ['a', '4', '@'],
      'e' => ['e', '3'],
      'i' => ['i', '1', '!'],
      'o' => ['o', '0'],
      's' => ['s', '5', '$'],
      't' => ['t', '7'],
      'l' => ['l', '1'],
      'g' => ['g', '9']
    }
    
    wordlist = [word]
    chars = word.downcase.chars
    
    chars.each_with_index do |char, i|
      if leet_map[char]
        leet_map[char].each do |replacement|
          new_word = word.dup
          new_word[i] = replacement
          wordlist << new_word
        end
      end
    end
    
    wordlist.uniq
  end

  def self.save_wordlist(wordlist, filename)
    File.write(filename, wordlist.join("\n"))
    filename
  end
end

