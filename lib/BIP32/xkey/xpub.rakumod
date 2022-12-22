need BIP32::xkey;
unit class BIP32::xkey::xpub does BIP32::xkey;

use secp256k1;
has Point $.Point;

method key { self.Point.Blob }

method version {
  %*ENV<BITCOIN_TEST> ?? 0x043587CF !! 0x0488B21E
}

