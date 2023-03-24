use Test;

use lib <lib>;
use Bitcoin;

use secp256k1;

# Example 6 from the bitcoin book, chap. 04
my $key = 0x3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6 but Bitcoin::PrivateKey;


is (G*$key).Blob,
  blob8.new("025C0DE3B9C8AB18DD04E3511243EC2952002DBFADC864B9628910169D9B9B00EC".comb(/../).map({:16($_)}));

is $key.address(:uncompressed), '1thMirt546nngXqyPEz532S8fLwbozud8';
is $key.address,                '14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3';

is $key.wif(:uncompressed), '5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K';
is $key.wif,                'KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S';


done-testing;

# vi: ft=raku
