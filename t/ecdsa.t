use Test;
use Bitcoin::EC;

plan 1;
my Bitcoin::EC::DSA::PrivateKey $key .= new: (10_000*rand).Int;

my ($r, $s) = $key.sign: my $msg = Buf.new: "Foo bar!".ords;
$key.public_key.verify: $msg, $r, $s ;
