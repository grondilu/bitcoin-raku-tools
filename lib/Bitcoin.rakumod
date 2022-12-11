unit module Bitcoin;
use Digest::SHA2;
use Digest::RIPEMD;
use Base58;
use Bitcoin::EC;

constant key-range is export = 1..^Bitcoin::EC::G.order;
subset privateKey of UInt is export where key-range;

sub checksum(Blob $b --> Blob) { sha256(sha256 $b).subbuf(0, 4) }
sub append-checksum(Blob $b --> Blob) { $b ~ checksum $b }

subset checkedB58Str of Str is export where /
  ^ <@Base58::alphabet>+ $
  <?{
    my $blob = Base58::decode ~$/;
    $blob.subbuf(*-4) ~~ checksum $blob.subbuf(0, *-4-1);
  }>
/;

sub WIF(privateKey $key, Bool :$uncompressed = False --> checkedB58Str) is export {
  Base58::encode append-checksum blob8.new:
    %*ENV<BITCOIN_TEST> ?? 0xef !! 0x80,
    $key.polymod(256 xx 31).reverse,
    $uncompressed ?? Empty !! 0x01
  ;
}

package P2PKH is export {
  our sub address(privateKey $key, Bool :$uncompressed = False --> checkedB58Str) {
     Base58::encode append-checksum
     blob8.new(0) ~ (&rmd160 ∘ &sha256)((Bitcoin::EC::G*$key).Blob(:$uncompressed))
  }
}

#vi: ft=raku
