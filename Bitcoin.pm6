#!/usr/local/bin/perl6
module Bitcoin;
use Bitcoin::Base58;

class Address is Bitcoin::Base58::Data {
    method size() { 160 }
    method default_version() { 0 }
}

class Key is Bitcoin::Base58::Data {
    method size { 256 }
    method default_version { 128 }
    method address returns Address {
	use Digest;
	return Address.new:
	Digest::rmd160::core
	Digest::sha256::core
	self.data;
    }
    multi method new() {
	self.Bitcoin::Base58::Data::new:
	Buf.new:
	map { (256*rand).Int }, ^32;
    }
}

