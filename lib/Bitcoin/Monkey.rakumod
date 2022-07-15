module Bitcoin::Monkey;
use MONKEY_TYPING;
=begin DESCRIPTION
This module gathers monkey patches used by the Perl6 bitcoin library.

Eventually this module will disappear but so far it has been quite convenient
to augment the Int class in order to easily perform conversion to fixed-sized
buffer.

You probably don't want to know much more than that.
=end DESCRIPTION

augment class Int {
    multi method Buf() returns Buf {
	my $n = self.clone;
	Buf.new: reverse gather repeat { take $n % 256; $n div= 256 } while $n > 0;
    }
    multi method Buf($size) returns Buf {
	my $n = self.clone;
	Buf.new: reverse gather for ^$size { take $n % 256; $n div= 256 };
    }
}

