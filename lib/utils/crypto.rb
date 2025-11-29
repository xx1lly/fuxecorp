require 'digest'
require 'base64'
require 'openssl'

module Crypto
  def self.hash_md5(text)
    Digest::MD5.hexdigest(text)
  end

  def self.hash_sha1(text)
    Digest::SHA1.hexdigest(text)
  end

  def self.hash_sha256(text)
    Digest::SHA256.hexdigest(text)
  end

  def self.hash_sha512(text)
    Digest::SHA512.hexdigest(text)
  end

  def self.xor_encrypt(text, key)
    encrypted = text.bytes.zip(key.bytes.cycle).map { |a, b| (a ^ b).chr }.join
    Base64.encode64(encrypted)
  end

  def self.xor_decrypt(encoded, key)
    encrypted = Base64.decode64(encoded)
    encrypted.bytes.zip(key.bytes.cycle).map { |a, b| (a ^ b).chr }.join
  end

  def self.generate_key(length = 32)
    (0...length).map { rand(36).to_s(36) }.join
  end

  def self.identify_hash(hash)
    case hash.length
    when 32 then 'MD5'
    when 40 then 'SHA1'
    when 64 then 'SHA256'
    when 128 then 'SHA512'
    else 'UNKNOWN'
    end
  end
end

