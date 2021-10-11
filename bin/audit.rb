#!/usr/bin/env ruby

puts "Server Assessment Tool v0.3"
puts "Enhanced system monitoring and security analysis"

# Display system information at startup
puts "\n=== System Information ==="
hostname = ENV['HOSTNAME'] || `hostname`.strip
os_info = `grep PRETTY_NAME /etc/os-release`.split('"')[1] rescue "Unknown"
kernel = `uname -r`.strip
uptime = `uptime -p`.strip

puts "Hostname: #{hostname}"
puts "OS: #{os_info}"
puts "Kernel: #{kernel}"
puts "Uptime: #{uptime}"

puts "\n=== Security Assessment ==="
# Check SSH config overrides first
ssh_config_overrides = `grep '^Include' /etc/ssh/sshd_config 2>/dev/null`.split.last

# Add some basic security checks
puts "Checking SSH configuration..."
ssh_root = `grep PermitRootLogin /etc/ssh/sshd_config`.strip
puts "SSH Root Access: #{ssh_root}"

# Check SSH port configuration
ssh_port = `grep "^Port" /etc/ssh/sshd_config`.strip
if ssh_port.empty?
  puts "SSH Port: 22 (default)"
else
  port_num = ssh_port.split.last.to_i
  if port_num > 1024
    puts "SSH Port: #{port_num} (unprivileged - potential security risk)"
  else
    puts "SSH Port: #{port_num}"
  end
end

puts "Checking firewall status..."
if `command -v ufw >/dev/null 2>&1 && echo "exists"`.strip == "exists"
  ufw_status = `ufw status`.include?("active") ? "ACTIVE" : "INACTIVE"
  puts "UFW Firewall: #{ufw_status}"
else
  puts "UFW Firewall: NOT INSTALLED"
end

puts "Checking for updates..."
updates = `apt list --upgradable 2>/dev/null | wc -l`.strip.to_i - 1
puts "Available updates: #{updates}"

puts "\n=== Port Analysis ==="
# Show exposed ports (optimized with -n flag)
listening_ports = `ss -tuln | grep LISTEN`.split("\n")
if listening_ports.any?
  ports = listening_ports.map { |line| line.split[4].split(':').last }.uniq.sort
  puts "Publicly exposed ports: #{ports.join(', ')}"
else
  puts "No publicly exposed ports detected"
end
