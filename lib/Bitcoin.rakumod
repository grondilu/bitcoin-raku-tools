module Bitcoin;
use Bitcoin::Base58;
use Bitcoin::EC;

=begin pod
=TITLE

Bitcoin.pm6, the main module of the bitcoin Perl6 library

=begin SYNOPSIS
    use Bitcoin;

    my Bitcoin::Address $addr       .= new: "178MmtztxxxxFAKExxxxxxGpDSZtnAJcZ5";
    my Bitcoin::Key     $key        .= new: "5JD4yrwxWxtfftvvhokE5bsj8i61xEez2LHVSRZfk99TxkYs56i";
    my Bitcoin::Key     $key .= new;
    my $key = Bitcoin::Key.new;

    say $addr.version;
    say $key.address;
    say $key + 1;

    class MyBitcoinDatabase does Bitcoin::Database {
	multi method block($hash) {
	   # some user, database specific code for block extraction
	   ...
	}
	multi method block($hash) {
	   # some user, database specific code for transaction extraction
	   ...
	}
    }

    say MyBitcoinDatabase.balance($addr);
=end SYNOPSIS

=begin DESCRIPTION

This is the main module for the Perl6 bitcoin library.

It allows the user to handle bitcoin keys and addresses.  The main features are:

=item checksum verification for existing bitcoin addresses ;
=item creation of new, random private keys ;
=item computation of the bitcoin address for a given private key ;
=item ECDSA signatures ;
=item elliptic curve arithmetics on private keys ;
=item Database role, implementing balance determination and block ordering,
provided the user implements block and transaction extraction (with a
particular database of his choice).;

Other features, such as block inspection, are provided by submodules:

=defn Bitcoin::Block
This class encapsulates a bitcoin block.  It can be instanciated
from a hex-dump of a block, or from a bitcoin::DataStream (see below).

=defn Bitcoin::Base58
This module performs Satoshi Nakamoto's base58 encoding/decoding.  It also
contains Bitcoin::Base58::Data, the base role for Bitcoin::Key and
Bitcoin::Address.

=defn Bitcoin::DataStream
This class performs data serialisation according to the bitcoin protocol.

=defn Bitcoin::Transaction
This class encapsulates a bitcoin transaction.

=defn Bitcoin::Script
This class encapsulates a bitcoin script.

=defn Bitcoin::EC
This module and its sub-packages provide elliptic curve arithmetics and
cryptography in I<secp256k1>.

=end DESCRIPTION

=begin DEPENDENCY

SHA-256 and RIPEMD-160 are needed in the 'Digest' module from the same author
at L<http://github.com/grondilu/libdigest-perl6>.

=end DEPENDENCY

=WARNING

Not only this is work in progress, but Perl6 itself is in its infancy.  So this
software really comes with no warranty whatsoever.  USE AT YOUR OWN RISK.


P<file:/usr/local/src/libbitcoin-perl6/COPYRIGHT>
=end pod

# A probably useful subset of Str called 'hexdump'
subset hexdump of Str where /^ 'Ox'? <[ 0..9 a..z ]> ** 64 $/;

class Address does Bitcoin::Base58::Data {
    our $.size = 160;
    our $.default_version = 0;
    multi method new(Bitcoin::EC::Point $public_point) { 
	use Bitcoin::Digest;
	self.new:
	Bitcoin::Digest::bin160
	[~] Buf.new(4),
	$public_point.x.Buf(32),
	$public_point.y.Buf(32);
    }
}

class Key is Bitcoin::EC::DSA::PrivateKey {
    also does Bitcoin::Base58::Data;
    our $.size = 256;
    our $.default_version = 128;
    multi method new { self.new: Buf.new: map {(^256).pick}, ^32 }
    method e returns Int { self.Int }
    method address returns Address { Address.new: self.public_key.point }
}

# We define a database as a role and not as a class because we want to be
# agnostic about any particular database implementation.
# Best would be BerkeleyDB for compatibility with Satoshi's code but BerkeleyDB
# will probably not be available for Perl6 any time soon :(
role Database {

    proto method block($) {*};
    proto method transaction($) {*};

    multi method block(int $n where * > 0) {
	use Bitcoin::Checkpoints;
	if defined %Bitcoin::Checkpoints::value{$n} {
	    return self.block: %Bitcoin::Checkpoints::value{$n};
	}
    }
    method balance(Address $addr) {...}

}
