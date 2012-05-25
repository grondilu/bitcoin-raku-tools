class Bitcoin::DataStream;

has Buf $.data is rw;
has $cursor = 0;

multi method new(Buf $buf?) { self.Mu::new: :data($buf || Buf.new) }
multi method new(Str $hexdump where /^ <[ 0..9 a..f ]>+ $/) { self.new: pack 'H*', $hexdump }

method write-compact-size(Int $size where * > 0) {
    $.data ~= pack |
    do given $size {
	when * < 253	{ 'C', $_ }
	when * < 2**16	{ 'CS', 253, $_ }
	when * < 2**32	{ 'CL', 254, $_ }
	default		{ 'CQ', 255, $_ }
    };
}

method read-compact-size returns Int {
    given $.data[$!cursor++] {
	when 253 { self.read-uint16 }
	when 254 { self.read-uint32 }
	when 255 { self.read-uint64 }
	default  { $_ }
    }
}

method read-string {
    my $length = self.read-compact-size;
    return $.data.subbuf($!cursor, $!cursor +$length-1).unpack('a*');
    LEAVE { $!cursor += $length }
}

multi method write-string(Buf $b) {
    self.write-compact-size: $b.list.elems;
    $.data ~= $b;
}
multi method write-string(Str $s) {
    # use bytes;  # NYI
    self.write-string: Buf.new: $s.ords;
}

multi method read-byte { Buf.new: $.data[$!cursor++] }
multi method read-byte($n) { [~] map {self.read-byte}, ^$n }
method read-int16  { LEAVE { $!cursor +=2 }; $.data.subbuf($!cursor, 2).unpack('s') }
method read-uint16 { LEAVE { $!cursor +=2 }; $.data.subbuf($!cursor, 2).unpack('S') }
method read-int32  { LEAVE { $!cursor +=4 }; $.data.subbuf($!cursor, 4).unpack('l') }
method read-uint32 { LEAVE { $!cursor +=4 }; $.data.subbuf($!cursor, 4).unpack('L') }
method read-int64  { LEAVE { $!cursor +=8 }; $.data.subbuf($!cursor, 8).unpack('q') }
method read-uint64 { LEAVE { $!cursor +=8 }; $.data.subbuf($!cursor, 8).unpack('Q') }

multi method write-byte(@c)   { $.data ~= Buf.new: @c }
multi method write-byte(Buf $b)   { $.data ~= $b }
method write-int16($i)  { $.data ~= pack 's', $i }
method write-uint16($i) { $.data ~= pack 'S', $i }
method write-int32($i)  { $.data ~= pack 'l', $i }
method write-uint32($i) { $.data ~= pack 'L', $i }
method write-int64($i)  { $.data ~= pack 'q', $i }
method write-uint64($i) { $.data ~= pack 'Q', $i }

method gist { "Bitcoin::DataStream:<{ $.data.list.join: ' ' }>" }
# vim: ft=perl6
