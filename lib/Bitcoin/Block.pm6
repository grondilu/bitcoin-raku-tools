class Bitcoin::Block;
use Bitcoin::DataStream;
use Bitcoin::Transaction;

our constant PROOF-OF-WORK-LIMIT = 32;

sub digest($s) { use Digest; Digest::sha256::core Digest::sha256::core $s }

class Header {
    has $.version;
    has Buf $.hashPrev;
    has Buf $.hashMerkleRoot;
    has Int $.nTime;
    has Int $.nBits;
    has Int $.nNonce;
    multi method new(Str $dump where /^ <[ 0..9 a..z ]>+ $/) { self.new: Bitcoin::DataStream.new: $dump }
    multi method new(Bitcoin::DataStream $stream) {
	given $stream {
	    return self.Mu::new:
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
	my $hash = digest self.serialize.data;
	!!! "not enough work" if $target < reduce * *256 + *, reverse $hash.list;
    }
    method serialize returns Bitcoin::DataStream {
	Bitcoin::DataStream.new:
	pack 'lC32C32LLL',
	$.version,
	|($.hashPrev, $.hashMerkleRoot)».list,
	$.nTime, $.nBits, $.nNonce;
    }
    method gist { self.serialize.gist }
}

has Header $.header;
has @.transactions;

multi method new(Str $dump where /^ <[ 0..9 a..z ]>+ $/) { self.new: Bitcoin::DataStream.new: $dump }
multi method new(Bitcoin::DataStream $stream) {
    self.Mu::new:
    :header(Header.new: $stream),
    :transactions(map {Bitcoin::Transaction.new: $stream}, ^$stream.read-compact-size),
    ;
}

method serialize returns Bitcoin::DataStream {
    my $stream = $.header.serialize;
    $stream.write-compact-size: @.transactions.elems;
    $stream.data ~= .serialize.data for @.transactions;
    return $stream;
}

method Merkle_tree {
    # This is a straightforward translation of Satoshi's code
    push my @tree, .get_hash for @.transactions;
    loop ( my ($j, $size) = (0, @.transactions.elems); $size > 1; $size = (($size + 1) / 2).Int ) {
	loop ( my $i = 0; $i < $size; $i += 2 ) {
	    my $i2 = $i + 1 < $size - 1 ?? $i + 1 !! $size - 1;
	    push @tree, digest @tree[$j + $i] ~ @tree[$j + $i2];
	}
	$j += $size;
    }
    return @tree;
}

