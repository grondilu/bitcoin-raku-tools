module Bitcoin;
use Bitcoin::Base58;
use Bitcoin::EC;

class Address is Bitcoin::Base58::Data {
    method size { 160 }
    method default_version { 0 }
    multi method new(Bitcoin::EC::Point $public_point) { 
	use Digest;
	self.Bitcoin::Base58::Data::new:
	Digest::rmd160::core
	Digest::sha256::core
	[~] Buf.new(4),
	$public_point.x.Buf(32),
	$public_point.y.Buf(32);
    }
}

class Key is Bitcoin::Base58::Data {
    method size { 256 }
    method default_version { 128 }
    multi method new() {
	self.Bitcoin::Base58::Data::new:
	Buf.new: map { (256*rand).Int }, ^32;
    }
    method public_point { Bitcoin::EC::G.mult: self.Int }
    method private_key { Bitcoin::EC::DSA::PrivateKey.new: self.Int }
    method address returns Address { Address.new: self.public_point }
    multi method sign(Buf $msg) { self.private_key.sign: $msg }
    multi method sign(Str $msg) { self.sign: Buf.new: $msg.ords }
}
