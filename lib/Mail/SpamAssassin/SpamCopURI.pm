package Mail::SpamAssassin::SpamCopURI;

use strict;
use URI;
use URI::QueryParam;
use URI::Escape qw(uri_unescape);

use vars qw($VERSION $MAX_RESOLVE_COUNT $LWP_TIMEOUT);

$MAX_RESOLVE_COUNT = 4; # XXX could make both of these config options
$LWP_TIMEOUT = 5;

$VERSION = 0.19;

my $IP_RE= qr/^[0-9]+(\.[0-9]+){3}$/;
my $HEX_IP_RE= qr/^(0x[a-f0-9]{2}|[0-9]+)(\.0x[a-f0-9]{2}|\.[0-9]+){3}$/i;

#$Mail::SpamAssassin::DEBUG->{enabled} = 1;

sub new {

  my $class = shift;

  $class = ref($class) || $class;

  my $msg  = shift || die "must supply a PerMsgStatus";

  my $self = {msg => $msg, redirect_cache => {}, rbl_cache => {}};

  bless ($self, $class);

  $self;
}

sub _resolve_url {

  my $self = shift;

  my $url = shift;

  # only run if we have LWP
  return undef unless eval {require LWP::UserAgent;};

  my $ua = LWP::UserAgent->new();
   
  # do this since we never want the content
  $ua->max_size(0);
  $ua->timeout($LWP_TIMEOUT);
  $ua->env_proxy;

  dbg("redirect resolving:  $url");

  my $rsp = $ua->simple_request(HTTP::Request->new(GET => $url));
   
  my $location = $rsp->header('Location');

  if ($rsp->code =~ /^30[0-9]$/ && $location) {
   
    dbg("resolved url :  $location");

    return $location;
  }

  return undef;
}

sub _fixup_url {
   my $url = shift;

   # do this because yahoo only requires a single slash :(
   # IE + Opera convert \ to /
   $url =~ s#^(http[s]?):([/\\]{1,2})#$1://#i;

 return $url;
}

# convert hosts that are completely numeric to IP
sub _debase10_host {

  my $host = shift;

  if (defined $host && $host =~ /^[0-9]+$/) {

    my $x = unpack("H*", pack("N*", $host ));

    my @ip;

    push @ip, hex($1)  while $x =~ /([a-z0-9]{2})/g;

    return join(".", @ip);

  } else {

    return $host;
  
  }

}

sub _dehex_host {

  my $host = shift;

  if (defined $host && $host =~ $HEX_IP_RE) {
      my $new_host = join (".", map { $_ =~ s/^(0x[a-f0-9]{2})$/hex($1)/ei; $_;}
                    split(/\./, $host));
      return $new_host;

  } else {

    return $host;

  }

}

sub _extract_urls {

  my $url = shift;

  $url = _fixup_url($url);

  my $u = URI->new($url);

  my $path = uri_unescape($u->path);

  my @urls = ($url);

  if ($path =~ m#(http[s]?:[\\/]{1,2}.*)#i) {
    push @urls, _extract_urls($1);
  }

  my $query = uri_unescape($u->query);

  # we want to be conservative here and use
  # the anchor since we can always get the URL 
  # from the query param if this doesn't hit
  if (defined $query && $query =~ m#(^http[s]?://.*)#i) {
    push @urls, _extract_urls($1);
  }

  for my $key ($u->query_param) {
    my $value = $u->query_param($key);

    # removing anchor to catch AOL case
    # where the link is buried in param
    if ($value =~ m#(http[s]?://.*)#i) {
      push @urls, _extract_urls($1);
    }
  }

  my %unique;
  @unique{@urls} = map {1} @urls;

  return keys %unique;
}


sub _fetch_cache {
  
  my $self = shift;

  my $origin = shift;

  my $cache = shift; 

  # currently this little cache
  # abstraction  is limited to one arg :)

  my $key  = shift;

  if (exists $cache->{$key}) {

    dbg("returning cached data :  $key -> $cache->{$key}");

    return $cache->{$key};

  } else {

    my $data = $origin->($self, $key, @_);

    $cache->{$key} = $data if defined $data;

    return $data;
  }
}

sub resolve_url {

  my $self = shift;

  return $self->_fetch_cache(\&_resolve_url, $self->{redirect_cache}, @_)
}

##############################################################################
# taken from SpamAssassin 3.0 development trunk
sub trim_domain_to_registrar_boundary {
  my ($domain) = @_;

  # drop any hostname parts, if we can.
  my @domparts = split (/\./, $domain);
  my $numparts = scalar @domparts;

  # for the HELO variant, drop the first bit of the HELO (ie. turn
  # "host.dom.ain" into "dom.ain".)
  if ($numparts > 0) {
    my $partsreqd = 2;

    # the "Demon case"; Demon Internet registers domains for
    # its customers, ie. "foo.demon.co.uk".
    if ($domain =~ /\. (?:
		      demon\.co\.uk
		      )$/ix)
    {
      $partsreqd = 4;
    }
    # Subdelegated CCTLD
    elsif (is_in_subdelegated_cctld ($domain)) {
      $partsreqd = 3;
    }

    while ($numparts > $partsreqd) {
      $domain =~ s/^[^\.]+\.//;
      $numparts--;
    }
  }
  $domain;
}


sub is_in_subdelegated_cctld {
  my ($domain) = @_;

  # http://www.bestregistrar.com/help/ccTLD.htm lists these
  return ($domain =~ /\.
	  (?:ac| ae| ar| at| au| az| bb| bm| br| bs| ca| cn| co|
	  cr| cu| cy| do| ec| eg| fj| ge| gg| gu| hk| hu| id| il| im|
	  in| je| jo| jp| kh| kr| la| lb| lc| lv| ly| mm| mo| mt| mx| my|
	  na| nc| ni| np| nz| pa| pe| ph| pl| py| ru| sg| sh| sv| sy| th|
	  tn| tr| tw| ua| ug| uk| uy| ve| vi| yu| za)
	$/ixo);
}

# take a URI and return a hash
#  basically a poor man's object
sub _spamcop_uri {

  my $self = shift;

  my $url = shift;

  return undef unless $url;

  my $u = URI->new($url); 

  my %url = (
    'as_string' => $u->as_string,
  );

  my @fields = qw(host path);

  foreach my $f (@fields) {
    # we do the boolean check to make sure that its not
    # empty  as in http:// which has an empty host
    $url{$f} = ($u->can($f) && $u->$f() ? $u->$f() : undef);
  }

  # convert IPs like 0xd5.172.31.16 to 213.172.31.16
  $url{host} = _dehex_host($url{host});

  # convert IPs like 1110325108 to 66.46.55.116  
  $url{host} = _debase10_host($url{host});

  # URI doesn't always put the port in the right place
  # so we strip it off here
  $url{host} =~ s/:[0-9]+$// if $url{host};

  if ($url{host} && $url{host} !~ $IP_RE) {

    # RFC 1034 Section 3.1 says there should only be letters, digits and
    # hyphens in a domain.  This is intended to clean up an encoding hack
    # spammers use to disguise their URLs.  
    # Example:  http://www=2eseo500=2ecom
    $url{host} =~ s/=2e/./g;


    # strip any non alpha characters off of the end
    # this is to fix a bug where url parsing in core SA
    # leaves parens and other junk on the URL that URI
    # parses to the host
    my @p = split(/\./, $url{host});
    if (@p) {
      $p[-1] =~ s/[^a-z].+$//i;
      $url{host} = join ('.', @p);
      $url{domain} = trim_domain_to_registrar_boundary($url{host});

    } else {

      $url{host} = '';
      $url{domain} = '';
    }
  }


  return \%url;
}

sub _query_rbl {

  my $self = shift;

  my $host = shift || die 'no host specified';

  my $msg = $self->{msg};

  return unless $msg->load_resolver();

  my $res = $msg->{res};

  dbg("querying for $host\n");

  my $query = $res->search($host);

  unless ($query) {
    dbg("Query failed for $host");
    return [];
  }

  my @addrs;
  foreach my $rr ($query->answer) {
    dbg("found A records for: $host");
    next unless $rr->type eq 'A';
    push @addrs, $rr->address;
  }

  return \@addrs;
}


sub query_rbl {

  my $self = shift;
  
  my $addrs =  $self->_fetch_cache(\&_query_rbl, $self->{rbl_cache}, @_) || [];

  return @$addrs;
}

sub _extract_redirect_urls {

  my $self = shift;

  # history of urls
  my @urls = @_;

  # look at only the last one
  my $sc_url = $self->_spamcop_uri($urls[-1]);

  return @urls unless $self->open_redirect($sc_url->{host});

  if (@urls > $MAX_RESOLVE_COUNT) {
    dbg("max resolve count $MAX_RESOLVE_COUNT hit for: $urls[0]");
    return @urls;
  }

  my $r_url = $self->resolve_url($sc_url->{as_string});

  if ($r_url) {
    return $self->_extract_redirect_urls(@urls, $r_url);
  } else {
    return @urls;
  }

}

sub _check_spamcop_rbl {

  my $self = shift;

  my $sc_url = shift || die "no sc_url";

  my $rhs = shift || die "no rhs";

  my $addr_match = shift || die "no address to match against";


  dbg("checking url: $sc_url->{as_string}");

  return 0 unless $sc_url->{host};

  my $host = $sc_url->{host};


  if ($self->whitelisted($host)) {
     dbg("host for $sc_url->{as_string} whitelisted");
     return 0;
  } elsif ($self->blacklisted($host)) {
    dbg("host for $sc_url->{as_string} blacklisted");
    $self->{msg}->test_log("$host is blacklisted in blacklist_spamcop_uri");
    return 1;
  }

  my $host_query;

  if ($sc_url->{host} =~ $IP_RE) {

    $host_query =  join '.', reverse split(/\./, $sc_url->{host});

  } else {

    $host_query = $sc_url->{domain};

  }

  my $match = 0;

  my @addrs = $self->query_rbl("$host_query.$rhs");

  if (grep {$_ eq $addr_match} @addrs) {
    $match = 1;
    $self->{msg}->test_log("$sc_url->{host} is blacklisted in URI RBL at $rhs");
  }

  return $match;
}


sub open_redirect {

  my $self = shift;
  my $host = shift;

  my $msg = $self->{msg};

  my $res = $msg->_check_whitelist($msg->{conf}->{open_redirect_list_spamcop_uri}, $host);

  return $res;

}

sub whitelisted {

  my $self = shift;
  my $host = shift;

  my $msg = $self->{msg};

  my $res = $msg->_check_whitelist($msg->{conf}->{whitelist_spamcop_uri}, $host);

  return $res;

}

sub blacklisted {

  my $self = shift;
  my $host = shift;

  my $msg = $self->{msg};

  my $res = $msg->_check_whitelist($msg->{conf}->{blacklist_spamcop_uri}, $host);

  return $res;
}

sub uniq {

  my @array = @_;

  my %hash;

  @hash{@array} = map {1} @array;

  return keys %hash;
}

sub dbg { Mail::SpamAssassin::dbg (@_); }

#sub dbg { warn(@_); }

1;

package Mail::SpamAssassin::PerMsgStatus;



sub check_spamcop_uri_rbl {

  my $self = shift;

  my $urls = shift || die "no urls provided";

  my $rhs = shift || die "no rhs provided";

  my $addr_match = shift || die "no addr_match provided";

  my $sc = Mail::SpamAssassin::SpamCopURI->new($self);


  my @urls;

  my @extracted_urls;

  foreach my $u (@$urls) {
    push @extracted_urls, Mail::SpamAssassin::SpamCopURI::_extract_urls($u);
  }

  @urls = Mail::SpamAssassin::SpamCopURI::uniq(@extracted_urls);

  if ($self->{conf}->{spamcop_uri_resolve_open_redirects}) {

    @extracted_urls = ();

    foreach my $u (@urls) {
      push @extracted_urls, $sc->_extract_redirect_urls($u);
    }

    @urls = Mail::SpamAssassin::SpamCopURI::uniq(@extracted_urls);
  }

  foreach my $u (@urls) {

    my $sc_url = $sc->_spamcop_uri($u);

    my $r = $sc->_check_spamcop_rbl($sc_url, $rhs, $addr_match);

    return $r if $r;
  }

  return 0;
}

1;

__END__

=head1 NAME

Mail::SpamAssassin::SpamCopURI - blacklist checking of URLs in email

=head1 SYNOPSIS

See INSTALL for rules.


You may blacklist/whitelist domains by using the whitelist_spamcop_uri or 
blacklist_spamcop_uri.  The wildcarding is identical to what is used 
for the core whitelists that ship with SA.

=head1 DESCRIPTION

The first checks that SpamCopURI does is against the whitelist/blacklist.
If the URL's host appears in the whitelist, then the test is an
immediate miss.  If the URL's host is in the blacklist, then the
test is an immediate hit.

This currently only checks URIs that support methods for host. 
These are typically just http, https, and ftp.


The network method tests the domain portion of the URI against
a RHS RBL DNS rbl list that is specified in a conf file. If
the domain appears in the RBL, then the test scores a hit.

If open redirect resolution is enabled, then the url's host
will be compared against the open_redirect_list_spamcop_uri
and if a match is found, then the an attempt is made to 
get the Location header from the redirect service without actually
fetching from the destination site.

A few changes had to be made to the SA core to allow this module
to function properly.  Specifically, Mail::SpamassAssassin::Conf
was modified to allow uri_eval tests.  Most of the code already existed,
but was commented out.  Instead of shipping patches, I have included
the full source to both Conf.pm and PerMsgStatus.pm from version 2.63
of SA.

=head1 COREQUISITES
 
 C<Net::DNS>

=head1 AUTHOR

Eric Kolve, ekolve@comcast.net

=head1 COPYRIGHT
 
SpamCopURI is distributed under Perl's Artistic license.
 
=head1 AVAILABILITY
 
The latest version of this plugin is available at:
 
  http://sourceforge.net/projects/spamcopuri
 
=cut
