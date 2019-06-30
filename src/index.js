// run 'npm install eth-crypto --save'

const EthCrypto = require("eth-crypto");

// const sender = EthCrypto.createIdentity();
// assign sender's privateKey, publicKey, address generated using openssl
const sender = {
  privateKey: "may-be-next-time",
  publicKey:
    "0eaa389de0bc6dbad1eb42ec211d629368ee97b380103b5edbe2a164f54811395c3ff49ad2bcaa8749cfdac0d3c40fab07e10b9c112a25de173d74bd24c46161",
  address: "2a130c6c33107a14077b4d5261f8ebb65b908779"
};

console.log("sender privateKey: ", sender.privateKey);
console.log("sender publicKey: ", sender.publicKey);
console.log("sender address: ", sender.address);

//const receiver = EthCrypto.createIdentity();
// assign receiver's publicKey, address from forum
const receiver = {
  publicKey:
    "14b885c6d9caf5af535223d13d26c533dd8e9e944aea23e35c4def640d5518b25e413c39a65b32c5a0a20623c6d07d9d669ad58cf76725c00449a18b47e15973",
  address: ""
};

console.log("receiver privateKey: ", receiver.privateKey);
console.log("receiver publicKey: ", receiver.publicKey);
console.log("receiver address: ", receiver.address);

const secretMessage =
  "How come your address here is: 0xd02d94bd482bddfd4fb5b6034a47c9a762d5888e and the address you used to respond to my public key and address thread is: 0xf3FdB491c25ab7462DBE5F9D669a06F90f696b2D ...happy to send you a Crypto Kitten if you're interested ...lmk which mainnet address you want me to send the CK to";

async function elk_encrypt_decrypt_answer() {
  console.log("............................");
  console.log("Encrypt and sign the message");
  console.log("............................");

  // sign the secret message with sender's private key
  const signature = EthCrypto.sign(
    sender.privateKey,
    EthCrypto.hash.keccak256(secretMessage)
  );
  console.log("signature: ", signature);

  // prepare the payload with secret message & signature
  const payload = {
    message: secretMessage,
    signature
  };
  console.log("payload: ", payload);

  // encrypt the payload with receiver public key
  const encrypted = await EthCrypto.encryptWithPublicKey(
    receiver.publicKey, // by encryping with receiver publicKey, only receiver can decrypt the payload with his/her privateKey
    JSON.stringify(payload) // we have to stringify the payload before we can encrypt it
  );
  console.log("encrypted: ", encrypted);

  // we convert the object into a smaller string-representation
  const cipherencryptedString = EthCrypto.cipher.stringify(encrypted);
  console.log("cipherencryptedString: ", cipherencryptedString);

  ///////////////////////////
  // receiver side decryption
  console.log("..............................");
  console.log("Decrypt and verify the payload");
  console.log("..............................");

  const mycipherencryptedString =
    "7c97a14bc76912cfcb75e3c06b7c5d44032ac54dcb2d2aa7f2750eeaf10b762aee7e91d7f8333ab8f3b0008a2f64c06d1260196b1c71d6fe7a2e6255ae362519d0900cb18de2f6e9aeda80ef7533bc4e6872ba3799f290fcd5d4f9f1cdd7e04c1e47cb9c2c73ed3c19a376bd4d29de11dae34c7e5d8d45eac0913a8db30fe406a0fe3aae0c2fd6c3279d5faa7214b4d95318e4f25a68975ca3838407894c37b68cb8b93ecb5442439493454876cf54ed982bbd1886494c421c3a9da6f5e1cd6d2fa472dddc8a3a3e2624420b8c8ebca6beb3e371509eba3514157f4a2787162636a027052099a0a2fdc65b3c8be4c1fff319c9299dbede40bb680789bd05fa791f088dd1d2fd4a376c124de6b6e621c0ca62799e3922c9482608603405635b0d4f89cbe2d88acc43549c4628159d37897cf7b0e22b058587f67885783f89b0a4ee0a5757e70907d6171bb62c7ee681d5453fcbf960008a38254e55c1b2f597bb1ee948a29e1cc564d95da09976f3a88a82095b97f41896ef5eff05714810da4b93404cf93e387f1fc464d29a9ee98a384c";
  console.log("mycipherencryptedString: ", mycipherencryptedString);

  // we parse the string into the object again
  const encryptedObject = EthCrypto.cipher.parse(mycipherencryptedString);
  console.log("encryptedObject: ", encryptedObject);

  // decrypt the encrypted message with you private key
  const decrypted = await EthCrypto.decryptWithPrivateKey(
    sender.privateKey,
    encryptedObject
  );
  const decryptedPayload = JSON.parse(decrypted);
  console.log("decryptedPayload: ", decryptedPayload);

  // check signature
  const senderAddress = EthCrypto.recover(
    decryptedPayload.signature,
    EthCrypto.hash.keccak256(decryptedPayload.message)
  );
  console.log("senderAddress: ", senderAddress);

  console.log(
    "Thank You: " +
      senderAddress +
      " ...for your Message: " +
      decryptedPayload.message
  );

  //////////////////////////////
  // receiver creating an answer
  console.log("..............................");
  console.log("Creating an answer");
  console.log("..............................");

  // preparing our answer to sender
  const answerMessage = "We managed to accomplish our week 01 assignment";
  console.log("answerMessage: ", answerMessage);

  // sign the secret answer with receiver's private key
  const answerSignature = EthCrypto.sign(
    receiver.privateKey,
    EthCrypto.hash.keccak256(answerMessage)
  );
  console.log("answerSignature: ", answerSignature);

  // prepare the answerPayload
  const answerPayload = {
    message: answerMessage,
    signature: answerSignature
  };
  console.log("answerPayload: ", answerPayload);

  // retreive sender's public key
  const senderPublicKey = EthCrypto.recoverPublicKey(
    decryptedPayload.signature,
    EthCrypto.hash.keccak256(payload.message)
  );
  console.log("sender PublicKey: ", senderPublicKey);

  // encrypt the answer with sender's public key
  const encryptedAnswer = await EthCrypto.encryptWithPublicKey(
    senderPublicKey,
    JSON.stringify(answerPayload)
  );
  console.log("encryptedAnswer: ", encryptedAnswer);

  document.getElementById("app").innerHTML =
    "all is well -- encrypted, decrypted, and answered";
}
elk_encrypt_decrypt_answer();
