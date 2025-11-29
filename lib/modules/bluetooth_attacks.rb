require_relative '../utils/colorize'

class BluetoothAttacks
  def self.generate_bluetooth_scan
    script = <<~SH
      #!/bin/bash
      
      if ! command -v hcitool &> /dev/null; then
          echo "hcitool not found. Install bluez."
          exit 1
      fi
      
      hcitool scan
      hcitool scan --flush
    SH
    
    filename = "bluetooth_scan_#{Time.now.to_i}.sh"
    File.write(filename, script)
    File.chmod(filename, 0755)
    puts Colorize.green("Bluetooth scan script saved: #{filename}")
    filename
  end

  def self.generate_bluetooth_spoof(target_mac, spoofed_mac)
    script = <<~SH
      #!/bin/bash
      
      TARGET="#{target_mac}"
      SPOOFED="#{spoofed_mac}"
      
      if ! command -v bdaddr &> /dev/null; then
          echo "bdaddr not found. Install bluez."
          exit 1
      fi
      
      bdaddr -i hci0 $SPOOFED
      hciconfig hci0 reset
    SH
    
    filename = "bluetooth_spoof_#{Time.now.to_i}.sh"
    File.write(filename, script)
    File.chmod(filename, 0755)
    puts Colorize.green("Bluetooth spoof script saved: #{filename}")
    filename
  end

  def self.generate_bluebug_attack(target_mac)
    script = <<~SH
      #!/bin/bash
      
      TARGET="#{target_mac}"
      
      if ! command -v bluetoothctl &> /dev/null; then
          echo "bluetoothctl not found. Install bluez."
          exit 1
      fi
      
      bluetoothctl connect $TARGET
      bluetoothctl pair $TARGET
    SH
    
    filename = "bluebug_#{Time.now.to_i}.sh"
    File.write(filename, script)
    File.chmod(filename, 0755)
    puts Colorize.green("Bluebug attack script saved: #{filename}")
    filename
  end
end

