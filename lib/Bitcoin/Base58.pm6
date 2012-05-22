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
class Data {  
    has Buf $.data;
    has $.version;

    method size returns Int {}
    method default_version returns Int {}
    method Int returns Int { reduce * *256 + *, self.data.list }

    multi method new(Buf $buffer, :$version = self.default_version) {
	??? "wrong buffer size ({$buffer.elems})" if 8*$buffer.elems != self.size;
	self.Mu::new: :data($buffer), :version($version)
    }
    multi method new(Str $base58) {
	my $n = decode $base58;
	my $version = $n div 256**4 div 2**self.size;
	my Int $checksum =  $n % 256**4;
	my Int $data = $n div 256**4 % 2**self.size;
	my $new = self.new: $data.Buf;
	!!! "wrong checksum" unless $checksum.Buf == $new.checksum;
	return $new;
    }
    method checksum {
	use Digest;
	Buf.new: (Digest::sha256::core Digest::sha256::core Buf.new($.version) ~ self.data)[^4];
    }
    method gist {
	my $s = encode reduce * *256 + *, ($.data ~ self.checksum).list;
	$s = '1' ~ $s if self.version == 0;
	return $s;
    }
}

