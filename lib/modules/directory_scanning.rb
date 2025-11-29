require 'uri'
require_relative '../utils/network'
require_relative '../utils/colorize'

class DirectoryScanning
  COMMON_DIRS = %w[admin backup config database db files images img js css assets upload download media static public private secret hidden test dev staging production admin.php config.php backup.sql .git .svn robots.txt sitemap.xml wp-admin wp-content wp-includes phpmyadmin cpanel webdav ftp mail server-status server-info]

  def self.scan(url, wordlist = nil, extensions = nil)
    wordlist ||= COMMON_DIRS
    found = []
    
    wordlist.each do |dir|
      test_url = url.end_with?("/") ? "#{url}#{dir}" : "#{url}/#{dir}"
      
      if extensions
        extensions.each do |ext|
          test_file = "#{test_url}.#{ext}"
          result = check_path(test_file)
          found << result if result
        end
      else
        result = check_path(test_url)
        found << result if result
      end
    end
    
    found
  end

  def self.check_path(url)
    begin
      response = Network.http_request(url)
      return nil unless response
      
      case response.code
      when "200"
        puts Colorize.green("Found: #{url} (200)")
        { url: url, code: "200", status: "found" }
      when "403"
        puts Colorize.yellow("Forbidden: #{url} (403)")
        { url: url, code: "403", status: "forbidden" }
      when "301", "302"
        location = response['Location']
        puts Colorize.cyan("Redirect: #{url} -> #{location}")
        { url: url, code: response.code, status: "redirect", location: location }
      else
        nil
      end
    rescue
      nil
    end
  end
end

