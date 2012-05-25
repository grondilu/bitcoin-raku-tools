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

{
    use MONKEY_TYPING;
    augment class Int {
	multi method Buf() returns Buf {
	    my $n = self.clone;
	    Buf.new: (gather repeat { take $n % 256; $n div= 256 } while $n > 0).reverse;
	}
	multi method Buf($size) returns Buf {
	    my $n = self.clone;
	    Buf.new: (gather for ^$size { take $n % 256; $n div= 256 }).reverse;
	}
    }
}

#| Base class for a versioned, checksumed, base58-encoded data structure.  aka CBase58Data
role Data {  
    has Buf $.data;
    has $.version;

    our $.size;
    our $.default_version;
    method Int returns Int { reduce * *256 + *, $.data.list }

    multi method new(Buf $buffer, :$version?) {
	??? 'wrong buffer size' if 8*$buffer.elems != $.size;
	self.bless: *, :data($buffer), :version($version // $.default_version)
    }
    multi method new(Str $base58) {
	my $n = decode $base58;
	my $version = $n div 256**4 div 2**$.size;
	my Int $ndata = $n div 256**4 % 2**$.size;
	my $new = self.new: $ndata.Buf: $.size div 8;
	my $checksum = $new.checksum;
	!!! "wrong checksum" unless $checksum == $n % 256**4;
	return $new;
    }
    method checksum returns Int {
	use Digest;
	reduce * *256 + *, 
	(
	    Digest::sha256::core
	    Digest::sha256::core
	    Buf.new: $.version, $.data.list
	).subbuf(0, 4).list;
    }
    method gist {
	my $s = encode
	self.checksum + 256**4 *
	(
	    $.version * 2**$.size +
	    reduce * *256 + *, $.data.list
	);
	return $.version == 0 ?? '1' ~ $s !! $s;
    }
}

