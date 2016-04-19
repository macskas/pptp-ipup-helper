#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Std;
use IO::Socket::INET;
use IO::Select;
use Socket;
use POSIX qw /strftime/;
use Sys::Hostname;

eval {
    require Net::DHCP::Packet;
    require Net::DHCP::Constants;

    Net::DHCP::Packet->import();
    Net::DHCP::Constants->import();

    1;
} or do {
    &do_error("Please install modules Net::DHCP::Packet, Net::DHCP::Constants). Debian/Ubuntu: apt-get install libnet-dhcp-perl. FreeBSD/MacOS: cpan install Net::DHCP::Packet");
};


my $DEBUG = 0;
my $SUBNET_ROUTE_ADD = 0;
my $DRY_RUN = 0;
my $route_type = "iproute2";
my $dhcp_netmask = -1;
my @allowed_route_types = ( "iproute2", "bsd", "route" );
# 6 - dns server
# 1 - subnet
# 15 - domain name
# 43 - vendor option
# 44 - netbios name servers
# 33 - static route
# 121 - classless static route
# 249 - classless ms
# 252 - 

sub do_error()
{
    my $msg = shift;
    print STDERR strftime "[%d/%b/%Y:%H:%M:%S] ", localtime;
    print STDERR "ERROR > $msg\n";
    exit(1);
}

sub do_info()
{
    my $msg = shift;
    print STDOUT strftime "[%d/%b/%Y:%H:%M:%S] ", localtime;
    print STDOUT "INFO  > $msg\n";
}

sub do_debug()
{
    if (!$DEBUG) {
	return 0;
    }
    my $msg = shift || "-";
    print STDOUT strftime "[%d/%b/%Y:%H:%M:%S] ", localtime;
    print STDOUT "DEBUG > $msg\n";
}


$SIG{'ALRM'} = sub {
    &do_error("ALARM Timeout reached. Exiting.");
    exit(1);
};

sub get_interface_address()
{
    eval {
	require 'sys/ioctl.ph';
    } or do {
	&do_error("Missing sys/ioctl.ph. For example: cd /usr/include; h2ph -r -l .; Or google for missing ioctl.ph");
    };

    my ($iface) = @_;
    my $socket;
    socket($socket, PF_INET, SOCK_STREAM, (getprotobyname('tcp'))[2]) || &do_error("unable to create a socket: $!");
    my $buf = pack('a256', $iface);
    if (ioctl($socket, SIOCGIFADDR(), $buf) && (my @address = unpack('x20 C4', $buf)))
    {
        return join('.', @address);
    }
    return 0;
}

sub decode_249()
{
    my $input = shift || 0;
    my @routemap = ();
    my $len = length($input);
    if ($len < 5) {
	return \@routemap;
    }
    my ($mask_width, $significant_octets, $i);
    my $bp = 0;

    
    while ($len > 0) {
	my $cur = {
	    'ip'	=> '',
	    'gateway'	=> ''
	};
	$mask_width = unpack("C", substr($input, $bp++, 1));
	if ($mask_width > 32) {
	    last;
	}
	$len--;
	$significant_octets = int(($mask_width + 7) / 8);
	if ($len < ($significant_octets + 4)) {
	    last;
	}
	
	if ($mask_width == 0) {
	    $cur->{'ip'} = 'default';
	} else {
	    my @octets = ();
	    for ($i = 0; $i < $significant_octets ; $i++) {
		my $octet = unpack("C", substr($input, $bp++, 1));
		push(@octets, $octet);
	    }
	    for ($i = $significant_octets ; $i < 4 ; $i++) {
		push(@octets, "0");
	    }
	    $cur->{'ip'} = join(".", @octets) . "/" . $mask_width;
	}
	my $gateway = inet_ntoa(substr($input, $bp, 4));
	$cur->{'gateway'} = $gateway;
	push(@routemap, $cur);
	$bp += 4;
	$len -= ($significant_octets + 4);
    }
    return \@routemap;
}

sub netmask2bits()
{
    my $in = shift;
    my $out = 32;
    my $decnm = unpack("N", inet_aton($in));
    while (($decnm & 1) == 0) {
	$decnm >>= 1;
	$out--;
    }
    return $out;
}

sub subnetfromipnm()
{
    my $ip = shift;
    my $nm = shift || 32;
    my $decip = unpack("N",inet_aton($ip));
    my $sip = $decip >> (32-$nm) << (32-$nm);
    return inet_ntoa(pack("N", $sip)) ."/$nm";
}

sub send_inform()
{
    my ($ipaddr, $hostname, $xid) = @_;
    my $handle = IO::Socket::INET->new(
    	Proto => 'udp',
        Broadcast => 1,
        PeerPort => '67',
        LocalPort => '68',
        LocalAddr => $ipaddr,
        PeerAddr => '255.255.255.255'
    ) || &do_error("Socket creation error: $@");

    my $request = Net::DHCP::Packet->new(
        	    Xid					=> $xid,
            	    Htype				=> 8,
                    Hlen				=> 0,
                    Secs				=> 300,
                    Ciaddr				=> $ipaddr,
                    DHO_DHCP_MESSAGE_TYPE()		=> DHCPINFORM(),
                    DHO_HOST_NAME()			=> $hostname,
                    DHO_VENDOR_CLASS_IDENTIFIER()	=> 'MSFT 5.0',
                    DHO_DHCP_PARAMETER_REQUEST_LIST()	=> "6 44 43 1 249 15 33 121"
                );
    $handle->send($request->serialize()) or &do_error("Error sending: $!");
    &do_debug("Request sent: ". $request->toString());
    $handle->close();
}

sub recv_inform()
{
    my $ipaddr = shift;
    my $xid = shift;
    my $timeout_soft = shift;
    my $timeout_hard = shift;
    
    &do_debug("Start listening on $ipaddr:68");
    my $handle = IO::Socket::INET->new(
		    Proto => 'udp',
                    Broadcast => 1,
                    LocalPort => '68',
                    LocalAddr => $ipaddr
    ) || &do_error("Socket creation error: $@");

    my $sel = new IO::Select($handle);
    my $routemap = [];
    my $giaddr = 0;
    alarm($timeout_hard);
    &do_debug("Receiving DHCP packets ...");
    while (1) {
	my @ready = $sel->can_read($timeout_soft);
	if (!scalar(@ready)) {
	    &do_error("Response timed out. (seconds=$timeout_soft)");
	    last;
	}
	my $sock = $ready[0];
	my $buf = "";
	if (! sysread($ready[0], $buf, 4096)) {
	    &do_error("recv failed: $!");
	    last;
	}
	&do_debug("Received a DHCP packet (length=".length($buf).")");
	my $response = new Net::DHCP::Packet($buf);
	if (!defined($response) || !$response) {
	    &do_debug("Unable to decode DHCP response");
	    next;
	}
	if ( $response->xid != $xid ) {
	    &do_debug("Response XID != my XID");
	    next;
	}
	
	$giaddr = $response->giaddr();
	if (!defined($giaddr) || $giaddr eq '0.0.0.0') {
	    $giaddr = 0;
	}
	my $subnet = $response->getOptionValue(1);
	if (defined($subnet) && length($subnet) >= 7) {
	    my $nm = &netmask2bits($subnet);
	    if ($nm < 32 && $nm > 0) {
		$dhcp_netmask = $nm;
	    }
	}
	&do_debug("DHCP Response: ". $response->toString());
	# try option 249
	my $msraw = $response->getOptionRaw(249);
	$routemap = &decode_249($msraw);

	# fallback to option 121
	if (!scalar @{$routemap}) {
	    my $msraw = $response->getOptionRaw(121);
	    $routemap = &decode_249($msraw);
	}
	alarm(0);
	last;
    }
    $handle->close();
    if ($SUBNET_ROUTE_ADD && $dhcp_netmask != -1 && $giaddr) {
	push(@{$routemap}, {
	    'ip' => &subnetfromipnm($ipaddr, $dhcp_netmask),
	    'gateway' => $giaddr
	});
    }
    return $routemap;
}

sub process_routemap()
{
    my $interface = shift;
    my $routemap = shift || [];

    my @commands = ();
    foreach my $cur (@{$routemap}) {
	if ($route_type eq 'iproute2') {
	    push(@commands, sprintf("ip ro add %s dev %s", $cur->{'ip'}, $interface));
	}
	elsif ($route_type eq 'route') {
	    push(@commands, sprintf("route add -net %s dev %s", $cur->{'ip'}, $interface));
	}
	elsif ($route_type eq 'bsd') {
	    push(@commands, sprintf("route add %s -interface %s", $cur->{'ip'}, $interface));
	}
    }
    foreach my $cmd (@commands) {
	if ($DRY_RUN) {
	    &do_info("I would run: ".$cmd);
	} else {
	    my $rc = system($cmd);
	    if ($rc != 0) {
		&do_error("Bailing out. Route command failed: $cmd");
	    }
	}
    }
}

sub show_help()
{
    print "Usage:\n";
    print "\t$0 -i <interface> [OPTION...]\n";
    print "\n";
    print "\n";
    print "DHCP route helper for PPTP VPN\n";
    print "Help options:\n";
    print "-h                      Show help options\n";
    print "\n";
    print "Application options:\n";
    print "\t-i <interface>        Set interface to send and receive DHCP requests - mandatory\n";
    print "\t-t <timeout>          Set soft timeout for receive dhcp messages - default 3 seconds\n";
    print "\t-x <timeout>          Set hard timeout for receiving dhcp messages (SIGALARM) - default: soft*3 seconds\n";
    print "\t-a <ip address>       Source IP address for packets and listening - default: automatic\n";
    print "\t-m <dhcp hostname>    Override DHCP client hostname\n";
    print "\t-r <type>             Route command type. Valid options: bsd, iproute2, route - default: iproute2\n";
    print "\t-s                    Add DHCP server pool subnet to routemap also. (DHCP subnet option) - disabled by default\n";
    print "\t-d                    Debug mode - disabled by default\n";
    print "\t-n                    dry run - dont add route, just print them\n";
    print "\n";
    exit(0);
}

sub main()
{
    our ($opt_i, $opt_h, $opt_m, $opt_t, $opt_x, $opt_a, $opt_d, $opt_r, $opt_s, $opt_n);
    getopts("i:x:t:a:hdm:r:sn");
    my $xid = int(rand(0xFFFFFFFF));
    my $interface = "";
    my $ipaddr = "";
    my $hostname = hostname;
    my $timeout_soft = 3;
    my $timeout_hard = $timeout_soft*3;


    if (defined($opt_h)) {
	&show_help();
    }
    
    if (defined($opt_i) && length($opt_i) > 0) {
	$interface = $opt_i;
    } else {
	&show_help();
    }
    
    if (defined($opt_a) && length($opt_a) > 0) {
	$ipaddr = $opt_a;
    } else {
        $ipaddr = &get_interface_address($interface);
        if (!$ipaddr) {
    	    &do_error("Unable to get ip address of interface: $interface");
        }
    }

    if (defined($opt_m) && length($opt_m) > 0) {
	$hostname = $opt_m;
    }

    if (defined($opt_t) && length($opt_t) > 0) {
	$timeout_soft = int($opt_t);
	$timeout_hard = $timeout_soft*3;
    }
    
    if (defined($opt_x) && length($opt_x) > 0) {
	$timeout_hard = int($opt_x);
    }

    if (defined($opt_d)) {
	$DEBUG = 1;
    }
    
    if (defined($opt_r) && length($opt_r) >= 3) {
	if (grep $_ eq $opt_r, @allowed_route_types) {
	    $route_type = $opt_r;
	} else {
	    &show_help();
	}
    }

    if (defined($opt_s)) {
	$SUBNET_ROUTE_ADD = 1;
    }

    if (defined($opt_n)) {
	$DRY_RUN = 1;
    }

    &do_info("Send DHCP inform broadcast message from $ipaddr ($hostname)");
    &send_inform($ipaddr, $hostname, $xid);
    &do_info("Receive DHCP reply. (timeout_soft=$timeout_soft, timeout_hard=$timeout_hard)");
    my $routemap = &recv_inform($ipaddr, $xid, $timeout_soft, $timeout_hard);
    &process_routemap($interface, $routemap);
}

&main();
