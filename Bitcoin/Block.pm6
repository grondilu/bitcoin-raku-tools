class Bitcoin::Block;
use Bitcoin::DataStream;
use Bitcoin::Transaction;

class Header {
    has int $.version;
    has Buf $.hashPrev;
    has Buf $.hashMerkleRoot;
    has Int $.nTime;
    has Int $.nBits;
    has Int $.nNonce;
    method check-proof-of-work {
	use Digest;
	my ($size, $n) = $.nBits / 16**6, $.nBits % 16**6;
	my $target = $n * 256**($size - 3);
	!!! "target doesn't provide minimum work" if $target > 2**(256 - Bitcoin::PROOF-OF-WORK-LIMIT) - 1;
	!!! "hash doesn't match nBits" if
	$target < reduce * *256 + *,
	Digest::sha256::core(Digest::sha256::core self.serialize).list;
    }
    method serialize returns Bitcoin::DataStream {
	Bitcoin::DataStream.new:
	[~] $.version.Buf(2),
	($.hashPrev, $.hashMerkleRoot,)».Buf(32),
	($.nTime, $.nBits, $.nNonce)».Buf(4);
    }
}

has Header $.header;
has @.transaction of Bitcoin::Transaction;

method serialize returns Bitcoin::DataStream {
    # This is probably not so simple, but it is a good start
    [~] (self.header, self.transaction)».serialize
}

