#!/usr/local/bin/perl6
module Bitcoin::Base58;
constant @B58 = <
      1 2 3 4 5 6 7 8 9
    A B C D E F G H   J K L M N   P Q R S T U V W X Y Z
    a b c d e f g h i j k   m n o p q r s t u v w x y z
>;
my %B58 = @B58 Z ^58;
my $B58 = [~] '<[', @B58, ']>';

our sub decode(Str $x) returns Int { $x ~~ /<$B58>$/ ?? %B58{$/} + 58*&?ROUTINE($/.prematch) !! 0 }
our sub encode(Int $n) returns Str { $n < 58 ?? @B58[$n] !! &?ROUTINE($n div 58) ~ @B58[$n%58] }

#| Base class for base58-encoded data with a version number and checksum
class Data {  # aka CBase58Data
    has Int $.version; # should be Buf[1] or uint8 instead of just 'Int'
    has Buf $.data;

    method default_version() {}
    method size() {}

    sub sha256($x) { use Digest; Digest::sha256::core $x; }
    sub BufToInt(Buf $b) { reduce * *256 + *, $b.list }
    sub IntToBuf(Int $n is copy) returns Buf {
	return Buf.new: (my @ = gather repeat { take $n % 256; $n div= 256 } while $n > 0).reverse;
    }

    multi method new(Buf $buffer, Int $version = self.default_version) { self.Mu::new: :data($buffer), :version($version) }
    multi method new(Str $base58) {
	my $n = decode $base58;
	my $checksum = $n % 256**4;
	my $version = $n div 256**4 div self.size;
	my $data = $n div 256**4 % self.size;
	self.new:
	:n(my $i = decode $base58),
	:version($i div 256**4 div 2**self.size)
    }
    multi method new(Int :$n, Int :$version) {
	my $data = IntToBuf $n div 256**4 % 2**self.size;
	my $new = self.Mu::new: :data($data), :version($version);
	!!! "wrong checksum" unless IntToBuf($n % 256**4) == $new.checksum;
	return $new;
    }
    method checksum {
	Buf.new:
	(sha256 sha256 Buf.new(self.version) ~ self.data)[^4];
    }
    method gist {
	encode BufToInt(
	    Buf.new(self.version) ~ self.data ~ self.checksum
	);
    }
}

