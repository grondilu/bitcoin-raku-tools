class Bitcoin::Block;
use Bitcoin::Digest;
use Bitcoin::DataStream;
use Bitcoin::Transaction;

=begin pod
=begin SYNOPSIS
    use Bitcoin::Block;

    my $hexgenesis = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
    my Bitcoin::Block $genesis .= new: $hexgenesis;
=end SYNOPSIS

=begin DESCRIPTION

The C<Bitcoin::Block> class encapsulates a bitcoin block.

The inner class C<Bitcoin::Block::Header> encapsulates a block header.

=end DESCRIPTION

=end pod

our constant PROOF-OF-WORK-LIMIT = 32;

class Header {
    has $.version;
    has Buf $.hashPrev;
    has Buf $.hashMerkleRoot;
    has Int $.nTime;
    has Int $.nBits;
    has Int $.nNonce;
    multi method new(Str $dump where /^ <[ 0..9 a..z ]>+ $/) {
	return self.new: Bitcoin::DataStream.new: $dump;
    }
    multi method new(Bitcoin::DataStream $stream) {
	given $stream {
	    return self.bless: *,
	    :version(        .read-int32	),
	    :hashPrev(       .read-byte(32)	),
	    :hashMerkleRoot( .read-byte(32)	),
	    :nTime(          .read-uint32	),
	    :nBits(          .read-uint32	),
	    :nNonce(         .read-uint32	),
	    ;
	}
    }
    method check-proof-of-work {
	my ($size, $n) = $.nBits div 16**6, $.nBits % 16**6;
	my $target = $n * 256**($size - 3);
	!!! "target ($target) doesn't provide minimum work" if $target > 2**(256 - PROOF-OF-WORK-LIMIT) - 1;
	my $hash = Bitcoin::Digest::bin256 self.serialize;
	!!! "not enough work" if $target < reduce * *256 + *, reverse $hash.list;
    }
    method serialize returns Buf {
	pack 'lC32C32LLL',
	$.version,
	|($.hashPrev, $.hashMerkleRoot)».list,
	$.nTime, $.nBits, $.nNonce;
    }
    method gist { self.serialize.gist }
}

has Header $.header;
has @.transactions;

multi method new(Str $dump where /^ <[ 0..9 a..z ]>+ $/) { return self.new: Bitcoin::DataStream.new: $dump }
multi method new(Bitcoin::DataStream $stream) {
    self.bless: *,
    :header(Header.new: $stream),
    :transactions(map {Bitcoin::Transaction.new: $stream}, ^$stream.read-compact-size),
    ;
}

method serialize {
    my $stream = Bitcoin::DataStream.new: $.header.serialize;
    $stream.write-compact-size: @.transactions.elems;
    $stream.data ~= .serialize for @.transactions;
    return $stream.data;
}

method Merkle-tree {
    # This is a straightforward translation of Satoshi's code
    push my @tree, Bitcoin::Digest::bin256 .serialize for @.transactions;
    loop ( my ($j, $size) = (0, @.transactions.elems); $size > 1; $size = (($size + 1) / 2).Int ) {
	loop ( my $i = 0; $i < $size; $i += 2 ) {
	    my $i2 = $i + 1 < $size - 1 ?? $i + 1 !! $size - 1;
	    push @tree, Bitcoin::Digest::bin256 @tree[$j + $i] ~ @tree[$j + $i2];
	}
	$j += $size;
    }
    return @tree;
}

