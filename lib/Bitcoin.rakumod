unit module Bitcoin;
use Digest::OpenSSL;
use Digest::RIPEMD;
use Base58;
use secp256k1;

constant key-range is export = 1..^secp256k1::G.order;

sub checksum(Blob $b --> Blob) { sha256(sha256 $b).subbuf(0, 4) }
sub append-checksum(Blob $b --> Blob) { $b ~ checksum $b }

subset checkedB58Str of Str is export where /
  ^ <@Base58::alphabet>+ $
  <?{
    my $blob = Base58::decode ~$/;
    $blob.subbuf(*-4) ~~ checksum $blob.subbuf(0, *-4-1);
  }>
/;

sub WIF(UInt $key where key-range, Bool :$uncompressed = False --> checkedB58Str) is export {
  Base58::encode append-checksum blob8.new:
    %*ENV<BITCOIN_TEST> ?? 0xef !! 0x80,
    $key.polymod(256 xx 31).reverse,
    $uncompressed ?? Empty !! 0x01
  ;
}

package P2PKH is export {
  our proto address(|) returns checkedB58Str is export {*}
  multi address(UInt $key where key-range, Bool :$uncompressed = False --> checkedB58Str) {
    samewith $key*secp256k1::G, :$uncompressed;
  }
  multi address(Point $point, Bool :$uncompressed = False) {
     Base58::encode append-checksum
     blob8.new(0) ~ rmd160 sha256($point.Blob(:$uncompressed))
  }
}

#vi: ft=raku
