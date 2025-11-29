require 'base64'
require_relative '../utils/crypto'
require_relative '../utils/colorize'

class Cryptography
  def self.hash(text, algorithm = :all)
    case algorithm
    when :md5
      { md5: Crypto.hash_md5(text) }
    when :sha1
      { sha1: Crypto.hash_sha1(text) }
    when :sha256
      { sha256: Crypto.hash_sha256(text) }
    when :sha512
      { sha512: Crypto.hash_sha512(text) }
    else
      {
        md5: Crypto.hash_md5(text),
        sha1: Crypto.hash_sha1(text),
        sha256: Crypto.hash_sha256(text),
        sha512: Crypto.hash_sha512(text)
      }
    end
  end

  def self.encrypt(text, key)
    Crypto.xor_encrypt(text, key)
  end

  def self.decrypt(encoded, key)
    Crypto.xor_decrypt(encoded, key)
  end

  def self.generate_key(length = 32)
    Crypto.generate_key(length)
  end

  def self.identify_hash(hash)
    Crypto.identify_hash(hash)
  end

  def self.base64_encode(text)
    Base64.encode64(text).strip
  end

  def self.base64_decode(encoded)
    Base64.decode64(encoded)
  end
end

