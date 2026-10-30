import ssh2 from "ssh2";

const { utils } = ssh2;

const failed = (v: unknown) => v instanceof Error || (Array.isArray(v) && v[0] instanceof Error);

export function generateEd25519(passphrase?: string): { private: string; public: string } {
  for (let attempt = 0; attempt < 50; attempt++) {
    const pair = passphrase === undefined
      ? utils.generateKeyPairSync("ed25519")
      : utils.generateKeyPairSync("ed25519", { passphrase, cipher: "aes256-ctr", rounds: 4 });
    if (!failed(utils.parseKey(pair.private, passphrase)) && !failed(utils.parseKey(pair.public))) return pair;
  }
  throw new Error("ssh2 could not generate a parseable ed25519 key");
}
