#!/usr/bin/env ruby

puts "Server Assessment Tool v0.2"
puts "Enhanced system monitoring and security analysis"

# Display system information at startup
puts "\n=== System Information ==="
hostname = `hostname`.strip
os_info = `grep PRETTY_NAME /etc/os-release`.split('"')[1] rescue "Unknown"
kernel = `uname -r`.strip
uptime = `uptime -p`.strip

puts "Hostname: #{hostname}"
puts "OS: #{os_info}"
puts "Kernel: #{kernel}"
puts "Uptime: #{uptime}"

puts "\n=== Security Assessment ==="
# Add some basic security checks
puts "Checking SSH configuration..."
ssh_root = `grep PermitRootLogin /etc/ssh/sshd_config`.strip
puts "SSH Root Access: #{ssh_root}"

puts "Checking for updates..."
updates = `apt list --upgradable 2>/dev/null | wc -l`.strip.to_i - 1
puts "Available updates: #{updates}"

puts "\n=== Port Analysis ==="
# Show exposed ports (optimized with -n flag)
listening_ports = `netstat -tuln | grep LISTEN`.split("\n")
if listening_ports.any?
  ports = listening_ports.map { |line| line.split[3].split(':').last }.uniq.sort
  puts "Publicly exposed ports: #{ports.join(', ')}"
else
  puts "No publicly exposed ports detected"
end
