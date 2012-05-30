module Bitcoin::Digest;
use Digest;

our sub hex256($x) { Digest::sha256::hex Digest::sha256::bin $x }
our sub bin256($x) { Digest::sha256::bin Digest::sha256::bin $x }

our sub hex160($x) { Digest::rmd160::hex Digest::sha256::bin $x }
our sub bin160($x) { Digest::rmd160::bin Digest::sha256::bin $x }
