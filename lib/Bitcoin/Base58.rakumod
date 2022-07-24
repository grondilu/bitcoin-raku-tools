unit module Bitcoin::Base58;
=begin pod
=TITLE 
Bitcoin::Base58,  Satoshi Nakamoto's base58 encoding

=begin SYNOPSIS
    use Bitcoin::Base58;
    say Bitcoin::Base58::encode 1_000;
    say Bitcoin::Base58::decode "14fkioPZzx";

    class MyData does Bitcoin::Base58::Data {
       our $.size = 160;
       our $.default_version = 0;
    }
    say MyData.new("zzz43rf").checksum;
=end SYNOPSIS

=begin DESCRIPTION

This module implements Satoshi Nakamoto's base58 encoding,
and defines a role for a checksummed, Base58 encoded data structure.
This role will be used by Bitcoin::Address and Bitcoin::Key.

=end DESCRIPTION

=WARNING
This module requires a monkey patch to convert integers to fixed-sized buffers.
See Bitcoin::Monkey.

=end pod

constant @B58 = <
      1 2 3 4 5 6 7 8 9
    A B C D E F G H   J K L M N   P Q R S T U V W X Y Z
    a b c d e f g h i j k   m n o p q r s t u v w x y z
>;
my %B58 = @B58 Z ^58;
my $B58 = [~] '<[', @B58, ']>';

our proto decode(Str $x) returns Blob {*}
our proto encode($)      returns Str  {*}

multi decode('') { Blob.new }
multi decode($s where /^1/) { Blob.new(0) ~ samewith $/.postmatch }
multi decode($s) { Blob.new: reduce * * 58 + *, %B58{$s.comb} }

multi encode(Blob $b) {
  if $b.elems > 1 and $b[0] == 0 { '1' ~ samewith $b.subbuf(1) }
  else { samewith reduce * * 256 + *, $b.list }
}
multi encode(0) { '1' }
multi encode(UInt $n) { @B58[$n.polymod(58 xx *).reverse].join }

#| Base role for a versioned, checksumed, base58-encoded data structure.  aka CBase58Data
role Data {  
    has Buf $.data;
    has $.version;

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
	use Bitcoin::Digest;
	reduce * *256 + *, 
	(
	    Bitcoin::Digest::bin256
	    Buf.new: $.version, $.data.list
	).subbuf(0, 4).list;
    }
    method gist {
	my $s = encode self.checksum + 256**4 * (
	    $.version * 2**$.size +
	    reduce * *256 + *, $.data.list
	);
	return $.version == 0 ?? "1$s" !! $s;
    }
}

