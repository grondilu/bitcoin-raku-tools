use Bitcoin::BIP32::ExtendedKey;
unit class Bitcoin::BIP32::ExtendedKey::Public does Bitcoin::BIP32::ExtendedKey;

use secp256k1;
has Point $.point;

method Point { $!point }
method key { self.Point.Blob }

method version {
  %*ENV<BITCOIN_TEST> ?? 0x043587CF !! 0x0488B21E
}

