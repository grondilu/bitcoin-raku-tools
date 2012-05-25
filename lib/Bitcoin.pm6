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
=end SYNOPSIS

=begin DESCRIPTION

This is the main module for the Perl6 bitcoin library.

It allows the user to handle bitcoin keys and addresses.  The main features are:

=item checksum verification for existing bitcoin addresses ;
=item creation of new, random private keys ;
=item computation of the bitcoin address for a given private key ;
=item easy elliptic curve arithmetics on private keys ;

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
This module provides elliptic curve arithmetics in I<secp256k1>.

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

our constant TEST = True;
our constant GENESIS = TEST ??
'00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008' !!
'000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f';
our constant MAX-BLOCK-SIZE	=   1_000_000;
our constant COIN		= 100_000_000;
our constant CENT		=   1_000_000;
our constant MAX-MONEY	=       21e14.Int;
our constant DEFAULT-PORT	=        8333;
our constant DUMMY-PASSWD	= 'dummy password';

class Address does Bitcoin::Base58::Data {
    our $.size = 160;
    our $.default_version = 0;
    multi method new(Bitcoin::EC::Point $public_point) { 
	use Digest;
	self.new:
	Digest::rmd160::core
	Digest::sha256::core
	[~] Buf.new(4),
	$public_point.x.Buf(32),
	$public_point.y.Buf(32);
    }
}

class Key does Bitcoin::Base58::Data {
    our $.size = 256;
    our $.default_version = 128;
    multi method new { self.new: Buf.new: map {(^256).pick}, ^32 }
    method public_point { Bitcoin::EC::G.mult: self.Int }
    method private_key { Bitcoin::EC::DSA::PrivateKey.new: self.Int }
    method address returns Address { Address.new: self.public_point }
    multi method sign(Buf $msg) { self.private_key.sign: $msg }
    multi method sign(Str $msg) {
	#use bytes;
	self.sign: Buf.new: $msg.ords;
    }
}
