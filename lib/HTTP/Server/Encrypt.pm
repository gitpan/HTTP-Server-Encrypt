package HTTP::Server::Encrypt;
use 5.008008;
use strict;
use warnings;
use Carp qw(croak);
use HTTP::Server::Daemon qw(become_daemon server_perfork_dynamic peer_info get_msg send_msg);
use HTTP::Status qw(status_message);
use HTTP::Date qw(time2str);
use MIME::Base64 qw(encode_base64);
use File::Basename qw(dirname basename);
use Sys::Sendfile qw(sendfile);
use Log::Lite qw(log logpath);
use Crypt::CBC;
use Digest::MD5 qw(md5_hex);
use Data::Dump qw(ddx);
use vars qw(@ISA @EXPORT_OK $right_auth $username $script_base_dir $peer_port $peer_ip $script %data $body %header $file %_GET %_POST %_HEAD %res $send_bytes $static_expires_secs $blowfish $blowfish_key $blowfish_encrypt $blowfish_decrypt $_POST %ip_allow %ip_deny $log_dir);

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(http_server_start);

our $VERSION = '0.03';

sub http_server_start
{
    my $ref_http_conf = shift;
    my %http_conf = %$ref_http_conf;
    my $port = $http_conf{'port'} || 80;
    my $protocol = $http_conf{'protocol'} || 'http';
    my $min_spare = $http_conf{'min_spare'} || 10;
    my $max_spare = $http_conf{'max_spare'} || 20;
    our $script_base_dir = $http_conf{'docroot'} || 'htdoc';
    our $static_expires_secs = $http_conf{'cache_expires_secs'} || 3600;
    our $username = $http_conf{'username'};
    my $passwd = $http_conf{'passwd'};
    my $blowfish_key = $http_conf{'blowfish_key'};
    our $blowfish_encrypt = $http_conf{'blowfish_encrypt'};
    our $blowfish_decrypt = $http_conf{'blowfish_decrypt'};
    our %ip_allow = %{$http_conf{'ip_allow'}} if $http_conf{'ip_allow'};
    our %ip_deny = %{$http_conf{'ip_deny'}} if $http_conf{'ip_deny'};
    our $log_dir = $http_conf{'log_dir'} if $http_conf{'log_dir'};
    $log_dir = '' if $log_dir eq 'no';
    logpath($log_dir) if $log_dir;

    if ($blowfish_key)
    {
        our $blowfish = Crypt::CBC->new( 
                            -key    => $blowfish_key ,
                            -cipher => 'Blowfish',
        );
    }

    if ($username or $passwd)
    {
        our $right_auth = encode_base64($username . ":" . $passwd);
        chomp $right_auth;
    }

    my ($package, $invoker) = caller;
    chdir( dirname($invoker) );

    my $pidfile = become_daemon($invoker);
    $SIG{TERM} = sub { unlink $pidfile; kill HUP => $$; };

    if (lc($protocol) eq 'perl')
    {
        server_perfork_dynamic(\&do_child_perl, $port, $min_spare, $max_spare);
    }
    else
    {
        server_perfork_dynamic(\&do_child_http, $port, $min_spare, $max_spare);
    }
    return $pidfile;
}

sub do_child_http
{
    my $sock = shift;
    local ($peer_port, $peer_ip) = peer_info($sock);
    if (%ip_allow) {return unless $ip_allow{$peer_ip};}
    if (%ip_deny)  {return if $ip_deny{$peer_ip};}
    my $status = 100;
    my $send_bytes;
    my $method;
    my $request_uri;
    my $protocol;
    my %header;

    my $chunk = http_readline($sock);
    if (!$chunk or length($chunk) > 16*1024)
    {
        $status = 414;
        goto HTTP_RESP;
    }

    ($method, $request_uri, $protocol) = $chunk =~ m/^(\w+)\s+(\S+)(?:\s+(\S+))?\r?$/;
    if ($method !~ /^(?:GET|POST)$/)
    {
        $status = 405;
        goto HTTP_RESP;
    }

    my ($script, $query_string ) = $request_uri =~ /([^?]*)(?:\?(.*))?/s;

    local %_GET;
    if($query_string)
    {
        my @query = split /\&/, $query_string;
        foreach (@query)
        {
            my ($k, $v) = $_ =~ /(.*)\=(.*)/;
            $_GET{$k} = $v;
        }
    }
    local %_HEAD = http_get_header($sock);

    if( -d "$script_base_dir$script" )
    {
        if (substr($script, -1) ne '/')
        {
            $status = 301;
            $header{'Location'} = "http://" . $_HEAD{'Host'} . "$script/$query_string";
            goto HTTP_RESP;
        }

        if (-e "$script_base_dir$script/index.html")
        {
            $script .= '/' if substr($script,-1) ne '/';
            $script .= 'index.html';
        }
        elsif (-e "$script_base_dir$script/index.htm")
        {
            $script .= '/' if substr($script,-1) ne '/';
            $script .= 'index.htm';
        }
        elsif (-e "$script_base_dir$script/index.pl")
        {
            $script .= '/' if substr($script,-1) ne '/';
            $script .= 'index.pl';
        }
    }
    my $script_file = "$script_base_dir$script";

    if ($right_auth)
    {
        my ($client_auth) = $_HEAD{'Authorization'} =~ /Basic\s*([\w\+\=]+)/ if $_HEAD{'Authorization'};
        unless (defined $client_auth and $client_auth eq $right_auth)
        {
            $status = 401;
            goto HTTP_RESP;
        }
    }

    local %_POST;
    local $_POST;
    if ($method eq 'POST')
    {
        use bytes;
        my $post_data = '';
        if(defined $_HEAD{'Content-Length'})
        {
            read($sock, $post_data, $_HEAD{'Content-Length'});
        }
        else
        {
            my $i = 0;
            while( substr($post_data, -2) ne "\015\012" )
            {
                read($sock, my $buf, 1);
                $post_data .= $buf;
                $i++;
                if ($i > 4096)
                {
                    $status = 411;
                    goto HTTP_RESP;
                }
            }
        }
        last unless $post_data;

        $post_data = $blowfish->decrypt($post_data) if $blowfish_decrypt;
        $_POST = $post_data;
        my @post_query = split /\&/, $post_data;
        foreach (@post_query)
        {
            my ($k_post, $v_post) = $_ =~ /(.*)\=(.*)/;
            $_POST{$k_post} = $v_post if $k_post;
        }
    }

    my $boolen_sendfile;
    my $body;
    if (-e $script_file and -r $script_file and -s $script_file)
    {
        eval
        {
            $status = 200;
            if ( substr( $script_file, -3) eq '.pl' )
            {
                no warnings;
                close STDOUT;
                open STDOUT,">",\$body or die "couldn`t open memory file: $!";
                unless (my $return = do $script_file)
                {
                    die "couldn`t parse $script_file: $@" if $@;
                    die "couldn`t do $script_file: $!"    unless defined $return ;
                    die "couldn`t run $script_file"       unless $return;
                }
            }
            else
            {
                open my $fh,"<",$script_file or die "couldn`t open file";
                binmode $fh;
                if(!$blowfish_encrypt)
                {
                    syswrite $sock, "HTTP/1.0 $status " . status_message($status) . "\015\012";
                    syswrite $sock, "Cache-Control: max-age=$static_expires_secs\015\012";
                    syswrite $sock, "\015\012";
                    $send_bytes = sendfile($sock, $fh);
                    $boolen_sendfile = 1;
                    goto HTTP_RESP;
                }
                else
                {
                    $body = do {local $/; <$fh>};
                }
                close $fh;
            }

            if($blowfish_encrypt)
            {
                $body = $blowfish->encrypt($body);
                $header{'Content-Type'} = "application/octet-stream";
            }
        };
        if($@)
        {
            $status = 500;
            $body = $@;
            goto HTTP_RESP;
        }
    }
    else
    {
        $status = 404;
        goto HTTP_RESP;
    }

    HTTP_RESP: $send_bytes = http_response($sock, $status, $body, %header) unless $boolen_sendfile;
    log('http_access', $peer_ip, $status, $method, $request_uri, $send_bytes, status_message($status), $@) if $log_dir;
    return $send_bytes;
}

sub http_get_header
{
    my $sock = shift;
    my @header;
    while ( my $line = http_readline($sock) ) 
    {
        last if ( $line =~ /^\s*$/ );
        my ($k, $v) = $line =~ /^([\w\-]+)\s*:\s*(.*)/;
        $v =~ s/[\015\012]//g;
        push @header, $k => $v;
    }
    return @header;
}

sub http_readline
{
    my $sock = shift;
    my $line;
    while ( read( $sock, my $buf, 1 ) ) 
    {
        last if $buf eq "\012";
        $line .= $buf;
    }
    return $line;
}

sub http_response
{
    my $sock = shift;
    my $status = shift || 200;
    my $body = shift;
    my %header = @_;

    my $status_msg = status_message($status);
    if (!$body and $status != 200 and $status != 301 and $status != 302 )
    {
        $body = "<title>$status $status_msg</title><h1>Colonel ERROR: $status $status_msg</h1><br/>";
    }
    $header{'Date'} = time2str(time) unless defined $header{'Date'};
    $header{'Server'} = 'Colonel/0.9 PERL/5.8' unless defined $header{'Server'};
    $header{'Content-Type'} = 'text/html' unless defined $header{'Content-Type'} ;
    use bytes;
    $header{'Content-Length'} = length($body) unless defined $header{'Content-Length'} ;
    $header{'WWW-Authenticate'} = 'Basic realm="Colonel Authentication System"' if $status == 401 ;

    my $head = "HTTP/1.0 $status $status_msg\015\012";
    foreach (keys %header)
    {
        $head .= "$_: " . $header{$_} . "\015\012";
    }

    my $output = $head . "\015\012" . $body;
    print $sock $output;
    return length($output);
}

1;
__END__

=head1 NAME

HTTP::Server::Encrypt - HTTP server with encrypt BODY section

=head1 SYNOPSIS

	use HTTP::Server::Encrypt qw(http_server_start);

	my %http_conf;
	$http_conf{'port'} = 80;
	$http_conf{'username'} = 'username';
	$http_conf{'passwd'} = 'passwd';
	$http_conf{'min_spare'} = 2;
	$http_conf{'max_spare'} = 6;
	$http_conf{'static_expires_secs'} = 7200;
	$http_conf{'docroot'} = 'plugins/';
	$http_conf{'blowfish_key'} = $key;
	$http_conf{'blowfish_encrypt'} = 'yes';
	$http_conf{'blowfish_decrypt'} = 'yes';
	$http_conf{'ip_allow'} = \%ip_allow;
	$http_conf{'ip_deny'} = \%ip_deny;
    $http_conf{'log_dir'} = '/var/log/httpd_encrype/';

	http_server_start(\%http_conf);


=head1 DESCRIPTION

A pure Perl WebServer with additional features below.

=over 4

=item *

Counld encrypt response BODY section or decrypt resquest BODY section with BlowFish CBC.

=item *

Support HTTP Basic Authentication.

=item *

Minimum and maximum number of prefork processes is configurable.

=item *

Cache static request`s response in memory. 

=item *

Route dynamic requests to file.

=item *

Built-in IP filter.

=item *

Support protocol I<PON> I<(Perl Object Notation)>.

=back


=head1 USAGE

Usage of I<HTTP::Server::Encrypt> is very simple.

=head2 http_server_start(%params)

To set up a new HTTP Server, call the I<http_server_start> method.
You Get All Done. It will run as a daemon.

If your want do things after I<http_server_start> method, you may use this:

    my $parent = fork();
    unless($parent)
    {
        http_server_start(\%http_conf);
        exit 1;
    }

    my $pidfile = __FILE__ . ".pid";
    for(1..9)
    {
        last if -s $pidfile;
        sleep 1;
    }

    ... #server already up. do your things ...

I<http_server_start> accepts the following named parameters in I<%params>:

=over 4

=item * port

The port of the daemon to which you wish to listen on.
Defaults to 80.

=item * protocol

Value I<http> for protocol HTTP.
Value I<pon> for protocol PON.

=item * min_spare

How many child will be forked when the server start.

=item * max_spare

Maximum number of processes can be forked.

=item * docroot

This directive sets the directory from which the server will serve files.
Request I<GET /script.pl> will be responsed by 
I</var/www/html/script.pl> if you this set to I</var/www/html/>.

=item * cache_expires_secs

Set the HTTP "Cache-Control: max-age" value for static content.

=item * username

Set the HTTP Basic Authentication username.

=item * passwd

Set the HTTP Basic Authentication password. if username and password are not be set, HTTP Basic Authentication disabled.

=item * blowfish_key

Set the BODY encrpyt key. if not set, BODY encrypt disabled.

=item * blowfish_encrypt

Set enable encrpy the send response BODY section.

=item * blowfish_decrypt

Set enable encrpy the recieved request BODY section.

=item * ip_allow

Set ip list allow acccess.

=item * ip_deny

Set ip list deny access.

=item * log_dir

Set log directory. Disable log if value eq I<no>.

=back


=head1 PERFORMANCE

The Module has about more the half of request/sec performance compared 
to apache 2.2.I got 3000 req/sec on Xeon 5520/8G which httpd got 6000. 
Your can trade off between req/sec and sec/req yourself using the 
config I<min_spare> and I<max_spare>. 


=head1 MSWin32 Support

This module have no plan to support MSWin32.


=head1 ABOUT PON

That is a very simple and friendly Network Protocol for PERL. I use it 
on my distributed system communication.Because it works just like JSON, 
I called it "PON".


=head1 AUTHOR

Written by ChenGang, yikuyiku.com@gmail.com

L<http://blog.yikuyiku.com/>


=head1 COPYRIGHT

Copyright (c) 2011 ChenGang.
This library is free software; you can redistribute it and/or 
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<HTTP::Daemon>, L<HTTP::Server::Simple>

=cut

