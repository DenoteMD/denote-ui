# Denote User Identify

## Instruction

We take care about your privacy, instead of username/password/email we offer you a new way to identify yourself without harm to your privacy.

## Features

- We using [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) to help you store remember your key pair.
- Your user's ID is digest of your public key
- Message will be signed/verified by using ECDSA in this case we use `secp256k1`

## Installation

```
npm i denoteui
```

## Example

Create a new key pair by call `DenoteUserIdentity.createNewUser()` or recover from a mnemonic words `DenoteUserIdentity.fromMnemonic(...)`.

```ts
import DenoteUserIdentity from 'denoteui';
const dui = new DenoteUserIdentity();
console.log('Mnemonic:\t', dui.getMnemonic());
console.log('User ID:\t', dui.getUserID());
```

Sign message:

```ts
const message = Buffer.from('Hello! this is example message');
const signedMessage = dui.sign(message);
console.log('Signed Message:\t', signedMessage.toString('base64'));
```

Recover user ID from signed message:

```ts
const recoveredUserID = DenoteUserIdentity.recoverUserID(signedMessage);
console.log('Recovered ID:\t', recoveredUserID);
const signedObj = dui.signObject({
  name: 'Chiro Hiro',
  age: 32,
  data: 'Hello',
});
```

Sign and recover object:

```ts
console.log('Singed object:\t', signedObj);
console.log('Recovered object:\t', JSON.stringify(DenoteUserIdentity.recoverObject(signedObj)));
```

## License

This software was licensed under [MIT License](https://github.com/DenoteMD/denoteui/blob/master/LICENSE)
