class Bitcoin::DataStream is Buf;
use Bitcoin::Base58;

# Eventually these types will be natively defined in rakudo
subset BYTE	of int;
subset CHAR	of int;
subset UCHAR	of int;
subset INT16	of int;
subset UINT16	of int;
subset INT32	of int;
subset UINT32	of Int;
subset INT64	of Int;
subset UINT64	of Int;
subset STRING	of Str;

has int $cursor = 0;

method read-compact-size returns Int {
    given self[$!cursor++] {
	when 253 { self.read: UINT16 }
	when 254 { self.read: UINT32 }
	when 255 { self.read: UINT64 }
	default { $_ }
    }
}

method write-compact-size(Int $size where { $_ > 0 } ) {
    self ~=
    do given $size {
	when * < 253	{ .Buf }
	when * < 2**16	{ 253.Buf ~ .Buf: 16 }
	when * < 2**32	{ 254.Buf ~ .Buf: 32 }
	default		{ 255.Buf ~ .Buf: 64 }
    }
}

#proto method read($) { !!! "empty datastream" unless self.elems; {*} }
our proto read($) {*}

multi method read(BYTE) { self[self.cursor++] }
multi method read(INT16) { -128*256	+ self.read: UINT16 }
multi method read(INT32) { -128*256**3	+ self.read: UINT32 }
multi method read(INT64) { -128*256**7	+ self.read: UINT64 }
multi method read(UINT16) {
    return reduce * *256+*, self[self.cursor «+« ^2];
    LEAVE { self.cursor += 2 }
}
multi method read(UINT32) {
    return reduce * *256+*, self[self.cursor «+« ^4];
    LEAVE { self.cursor += 4 }
}
multi method read(UINT64) {
    return reduce * *256+*, self[self.cursor «+« ^2];
    LEAVE { self.cursor += 8 }
}
multi method read(STRING) {
    my $length = self.read-compact-size;
    return self[self.cursor «+« ^$length];
    LEAVE { self.cursor += $length }
}

# vim: ft=perl6
