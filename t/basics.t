use Bitcoin;
use secp256k1;
use Test;

# Example 6 from the bitcoin book, chap. 04
my $key = 0x3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6;

is (G*$key).Blob,
  blob8.new("025C0DE3B9C8AB18DD04E3511243EC2952002DBFADC864B9628910169D9B9B00EC".comb(/../).map({:16($_)}));

is P2PKH::address($key, :uncompressed), '1thMirt546nngXqyPEz532S8fLwbozud8';
is P2PKH::address($key),                '14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3';

is ($key but WIF[:uncompressed]).gist, '5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K';
is ($key but WIF).gist,                'KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S';


done-testing;

# vi: ft=raku
