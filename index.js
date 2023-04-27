const ecc = require("eosjs-ecc");
const bip39 = require("bip39");
const HDKey = require("hdkey");
const wif = require("wif");

// Function to sign a message using a mnemonic (seed phrase)
async function signMessage(mnemonic, message) {
  // Generate the private key from the mnemonic
  let active = await getPublicPrivateKeyFromMnemonic(mnemonic, 0, "owner");

  console.log(active);

  // Sign the message using the private key
  const signedMessage = ecc.sign(message, active.priv_key);
  console.log("Signed Message:", signedMessage);

  return { signedMessage, publicKey: active.pub_key };
}

// Function to verify a signed message using the public key
function verifySignature(signedMessage, publicKey, message) {
  const isValid = ecc.verify(signedMessage, message, publicKey);
  console.log("Is the signature valid?", isValid);
  return isValid;
}

async function getPublicPrivateKeyFromMnemonic(mnemonic, accno, parent) {
  const seed = await bip39.mnemonicToSeedSync(mnemonic);
  const master = await HDKey.fromMasterSeed(Buffer.from(seed));
  const node = await master.derive("m/44'/194'/0'/0/" + accno + "");
  const pub_key = await ecc.PublicKey(node._publicKey).toString();
  const priv_key = await wif.encode(128, node._privateKey, false);
  const respObj = {
    priv_key: priv_key,
    pub_key: pub_key,
    parent,
  };
  return respObj;
}

// Example usage
(async () => {
  try {
    const mnemonic =
      "jeans problem tide hybrid island swarm sadness ridge ceiling daughter chaos laundry";
    const message = "Hello, EOS!";

    const { signedMessage, publicKey } = await signMessage(mnemonic, message);
    const isValid = verifySignature(signedMessage, publicKey, message);

    console.log("Signature verification:", isValid ? "Passed" : "Failed");
  } catch (error) {
    console.log("error in verify", error);
  }
})();
