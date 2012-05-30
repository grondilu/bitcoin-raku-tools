class Bitcoin::Transaction;
use Bitcoin::DataStream;
use Bitcoin::Script;

has $.version;
has (@.txIn, @.txOut);
has $.locktime;

class txIn  { has ($.prevout_hash, $.prevout_n, $.scriptSig, $.sequence) }
class txOut { has ($.value, $.scriptPubKey) }

multi method new(Bitcoin::DataStream $stream) {
    self.bless: *, 
    version => $stream.read-int32,						#1
    txIn => 
    eager( # eager is needed to ensure sequential evaluation
	map { 
	    txIn.new:
	    prevout_hash => $stream.read-byte(32),				#3
	    prevout_n    => $stream.read-uint32,				#4
	    scriptSig    => Bitcoin::Script.new($stream.read-string),		#5
	    sequence     => $stream.read-uint32,				#6
	}, ^$stream.read-compact-size						#2
    ),
    txOut => 
    eager( # eager is needed to ensure sequential evaluation
	map {
	    txOut.new:
	    value        => $stream.read-int64,					#8
	    scriptPubKey => Bitcoin::Script.new($stream.read-string),		#9
	}, ^$stream.read-compact-size						#7
    ),
    locktime => $stream.read-uint32						#10
    ;
}

method serialize {
    my Bitcoin::DataStream $stream .= new;
    for $stream {
	.write-int32: $.version;						#1
	.write-compact-size: @.txIn.elems;					#2
	for @.txIn -> $txIn {
	    .write-byte:	$txIn.prevout_hash.list;			#3
	    .write-uint32:	$txIn.prevout_n;				#4
	    .write-string:	$txIn.scriptSig.buffer;				#5
	    .write-uint32:	$txIn.sequence;					#6
	}
	.write-compact-size: @.txOut.elems;					#7
	for @.txOut -> $txOut {
	    .write-int64:	$txOut.value;					#8
	    .write-string:	$txOut.scriptPubKey.buffer;			#9
	}
	.write-uint32: $.locktime;						#10
    }
    return $stream.data;
}
# vim: ft=perl6
