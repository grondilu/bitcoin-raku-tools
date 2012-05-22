use Test;
use Bitcoin;

my %key = <
    16PRgUZvCneM7AYJ94TaoGE4rMQnRdqqt4	5JkYWudPXkXHkmayfUz52WsweFpY7saT4V9vh4ZNtWgFLLwNgej
    1KDxAxej4NZMQtao9xZGiadbsqxcKJt9Ng	5J4G4vaBCiAF881AMEEyc8uC2EHgLfCFP4BL97EvD5vnH99yC6p
    1PnA88ck7hGSsSqpPXhaVbWL3suWXEqfsF	5KKGiz5ViCpSXzWCm9ff48g5AdK54FR3w1ByrhQDb1U6kgjmgr2
    12jXM28Awqgm2NPgiD6EVjZmih66U5mUAt	5JfTp8uzBFzcJWhjrb7wJfevehwjT6c3WCBcYivpoRcjaSAgHtZ
    1BV1GXQmBKF6v6CqUjH6y95KNXqtCoLNWH	5JGcHNTEqrYGVuE2sRw2Ys26xY51ypm4c1dnfZGyw8naAUjkdGM
>;

plan %key.keys.elems;

is Bitcoin::Key.new(%key{$_}).address.gist, $_ for %key.keys;



# vim: ft=perl6
