CREATE TABLE block (
    hash char(32) binary primary key,
    version	integer,
    hashPrev		char(32) binary not null,
    hashMerkleRoot	char(32) binary not null,
    nTime	integer unsigned not null,
    nBits	integer unsigned not null,
    nNonce      integer unsigned not null,

    totalWork	integer unsigned,
    depth	integer unsigned,

    key (hashMerkleRoot)
);
CREATE TABLE chain ( lastHash char(32) binary primary key );

CREATE TABLE block_chain (
    block char(32) binary not null,
    chain char(32) binary not null,
    primary key (block, chain)
);

CREATE TABLE transaction (
    hash char(32) binary primary key,
    version integer,
    lockTime integer unsigned,
    coinbase boolean
);

CREATE TABLE Merkle_Tree (
    root char(32) unsigned not null,
    idx  integer unsigned,
    primary key (root, idx),
    key (root)
);

