#!perl -w

use Test::More tests => 8;
use Mail::SpamAssassin::SpamCopURI;
use Mail::SpamAssassin::PerMsgStatus;



eval {
  my $sc = Mail::SpamAssassin::SpamCopURI->new();
};

ok($@ =~ /must supply a PerMsgStatus/, 
   'constructor dies with error when missing PerMsgStatus');

my $msg = Mail::SpamAssassin::PerMsgStatus->new;
my $sc = Mail::SpamAssassin::SpamCopURI->new($msg);

my $sc2 = $sc->new($msg);
ok(ref($sc2) eq 'Mail::SpamAssassin::SpamCopURI', 
  'constructor works with blessed reference');

# just for Devel::Cover kicks
eval {$sc = Mail::SpamAssassin::SpamCopURI::new()};
ok($@ =~ /must supply a PerMsgStatus/, 
   'constructor dies with error when missing self');

my $malformed_url = 'http://www.yahoo.com)foo';

my $sc_url = $sc->_spamcop_uri($malformed_url);
ok($sc_url->{host} eq 'www.yahoo.com', 'trailing paren is stripped off of the end');

$sc_url = $sc->_spamcop_uri('http://');

ok($sc_url->{as_string} eq 'http://');

$sc_url = $sc->_spamcop_uri('');

ok(!defined $sc_url, 'sc not defined when empty string passed in');

$sc_url = $sc->_spamcop_uri('http://www=2eseo500=2ecom');

ok($sc_url->{host} eq 'www.seo500.com', '=2e was cleaned up');

my @list = qw( a a b b c c );

my @uniq = Mail::SpamAssassin::SpamCopURI::uniq(@list);

ok(eq_set(\@uniq, [qw(a b c)]), 'uniq thing works');



