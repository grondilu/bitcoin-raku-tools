unit module Bitcoin;
use Digest::SHA2;
use Digest::RIPEMD;
use Base58;
use secp256k1;

sub checksum(Blob $b --> Blob) { sha256(sha256 $b).subbuf(0, 4) }
sub append-checksum(Blob $b --> Blob) { $b ~ checksum $b }

subset checkedB58Str of Str is export where /
  ^ <@Base58::alphabet>+ $
  <?{
    my $blob = Base58::decode ~$/;
    $blob.subbuf(*-4) ~~ checksum $blob.subbuf(0, *-4-1);
  }>
/;

our package P2PKH {
  our proto address(|) returns checkedB58Str is export {*}
  multi address(UInt $key where 1..^secp256k1::G.order, Bool :$uncompressed = False --> checkedB58Str) {
    samewith $key*secp256k1::G, :$uncompressed;
  }
  multi address(Point $point, Bool :$uncompressed = False) {
     Base58::encode append-checksum
     blob8.new(0) ~ rmd160 sha256($point.Blob(:$uncompressed))
  }
}

our role PrivateKey {
  submethod TWEAK { die "integer out of range" unless self ~~ 1..secp256k1::G.order }
  method wif(Bool :$uncompressed = False) returns checkedB58Str {
    Base58::encode append-checksum blob8.new:
      %*ENV<BITCOIN_TEST> ?? 0xef !! 0x80,
      self.polymod(256 xx 31).reverse,
      $uncompressed ?? Empty !! 0x01
      ;
  }
  multi method address(:$uncompressed = False) {
    P2PKH::address self, :$uncompressed;
  }
}

#vi: ft=raku
