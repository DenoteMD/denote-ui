import bs58 from 'bs58';
import { sha512, ripemd160, sha256 } from 'hash.js';
import { ec as EC, curve } from 'elliptic';
import { Buffer } from 'safe-buffer';
import BN from 'bn.js';
import * as bip39 from 'bip39';

export * from './utilities';

const prefix = 'DenoteUI@\x00\x00\x00\x00\x00\x00\x00\x00:';
const noncePosition = prefix.indexOf('@') + 1;
const randomSalt = noncePosition + 4;
const prefixLength = prefix.length;
const rLength = 32;
const sLength = 32;
const rsLength = rLength + sLength;
const vLength = 1;
const jLength = 1;
const sigLength = rLength + sLength + vLength + jLength;

export interface IVerifySignedProof {
  message: string;
  nonce: number;
  signer: string;
}

export interface IRecoveredObject {
  signer: string;
  nonce: number;
  obj: object;
}

/**
 * Denote User Identity
 * @export
 * @class DenoteUserIdentity
 */
export class DenoteUserIdentity {
  /**
   * Store mnemonic if possible
   * @private
   * @type {string}
   * @memberof DenoteUserIdentity
   */
  private mnemonic: string = '';

  /**
   * Store key pair
   * @private
   * @type {EC.KeyPair}
   * @memberof DenoteUserIdentity
   */
  private keyPair: EC.KeyPair;

  /**
   * Cache user id to saving computing power
   * @private
   * @type {string}
   * @memberof DenoteUserIdentity
   */
  private cachedUserID: string = '';

  /**
   * Creates an instance of DenoteUserIdentity.
   * @param {string} [mnemonic] If mnemonic was not set we will create a new one
   * @memberof DenoteUserIdentity
   */
  constructor(mnemonic?: string) {
    this.mnemonic = mnemonic || bip39.generateMnemonic();
    const ec = new EC('secp256k1');
    // New elliptic private key from sha512(entropy(mnemonic))
    this.keyPair = ec.keyFromPrivate(sha512().update(bip39.mnemonicToEntropy(this.mnemonic)).digest());
  }

  /**
   * Get mnemonic
   * @return {*}  {string}
   * @memberof DenoteUserIdentity
   */
  public getMnemonic(): string {
    return this.mnemonic;
  }

  /**
   * Sign and serialized message
   * @param {Buffer} message
   * @return {*}  {Buffer}
   * @memberof DenoteUserIdentity
   */
  public sign(message: Buffer): Buffer {
    const ec = new EC('secp256k1');
    // Packed v,j in the same buffer
    const vj = Buffer.alloc(2);
    // Reserved uint64 for timestamp, please aware of year 2038 issue
    const prefixedMessage = Buffer.allocUnsafe(message.length + prefixLength);
    prefixedMessage.write(prefix, 0);
    // Write timestamp to place holder, timestamp was used as nonce
    // eslint-disable-next-line no-bitwise
    prefixedMessage.writeUInt32BE(((Date.now() / 1000) & 0xffffffff) >>> 0, noncePosition);
    // eslint-disable-next-line no-bitwise
    prefixedMessage.writeUInt32BE((Math.random() * 0xffffffff) >>> 0, randomSalt);
    message.copy(prefixedMessage, prefixLength);
    const messageDigest = new BN(sha256().update(prefixedMessage).digest('hex'), 'hex', 'be');
    const signature: EC.Signature = this.keyPair.sign(messageDigest);
    const qPrime = new BN(this.keyPair.getPublic().encode('hex', false), 'hex', 'be');
    // Store v and j
    vj.writeUInt8(signature.recoveryParam || 0, 0);
    vj.writeUInt8(ec.getKeyRecoveryParam(undefined, signature, qPrime), 1);

    const serializedBuf = Buffer.alloc(prefixedMessage.length + sigLength);
    serializedBuf.write(signature.r.toString('hex', 64), 0, rLength, 'hex');
    serializedBuf.write(signature.s.toString('hex', 64), rLength, sLength, 'hex');
    vj.copy(serializedBuf, rLength + sLength);
    prefixedMessage.copy(serializedBuf, sigLength);
    // Serialized form
    return serializedBuf;
  }

  /**
   * Sign an object
   * @param {*} obj
   * @return {*}  {string}
   * @memberof DenoteUserIdentity
   */
  public signObject(obj: object): string {
    return this.sign(Buffer.from(JSON.stringify(obj))).toString('base64');
  }

  /**
   * Get user ID of current key pair
   * @return {*}
   * @memberof DenoteUserIdentity
   */
  public getUserID() {
    if (this.cachedUserID.length > 0) {
      return this.cachedUserID;
    }
    if (typeof this.keyPair !== 'undefined') {
      this.cachedUserID = DenoteUserIdentity.publicKeyToUserID(this.keyPair.getPublic().encode('array', false));
      return this.cachedUserID;
    }
    throw new Error('Key pair is undefined can not get ID');
  }

  /**
   * Get UserID from public key
   * base58(ripemd160(publicKey))
   * @static
   * @param {(string | number[])} pubKey
   * @return {*}  {string}
   * @memberof DenoteUserIdentity
   */
  public static publicKeyToUserID(pubKey: string | number[]): string {
    let pubKeyDigest: number[];
    if (typeof pubKey === 'string') {
      pubKeyDigest = ripemd160().update(pubKey, 'hex').digest();
    } else {
      pubKeyDigest = ripemd160().update(pubKey).digest();
    }
    return bs58.encode(pubKeyDigest);
  }

  /**
   * Recover user ID from signed message
   * @static
   * @param {Buffer} signedMessage
   * @return {*}  {string}
   * @memberof DenoteUserIdentity
   */
  public static recoverUserID(signedMessage: Buffer): string {
    const ec = new EC('secp256k1');
    const r = new BN(signedMessage.slice(0, rLength).toString('hex'), 'hex', 'be');

    const s = new BN(signedMessage.slice(rLength, rsLength).toString('hex'), 'hex', 'be');
    const recoveryParam = signedMessage.readUInt8(rsLength);
    const j = signedMessage.readUInt8(rsLength + vLength);
    const message = signedMessage.slice(sigLength);
    const messageDigest = new BN(sha256().update(message).digest('hex'), 'hex', 'be');
    const pubKey = ec.recoverPubKey(
      messageDigest,
      {
        r,
        s,
        recoveryParam,
      },
      j,
    );
    return DenoteUserIdentity.publicKeyToUserID((<curve.base.BasePoint>pubKey).encode('hex', false));
  }

  /**
   * Verify a signed proof
   * @static
   * @param {Buffer} signedMessage
   * @return {*}  {IVerifySignedProof}
   * @memberof DenoteUserIdentity
   */
  public static verifySignedProof(signedMessage: Buffer): IVerifySignedProof {
    return {
      message: signedMessage.slice(sigLength + prefixLength).toString('hex'),
      nonce: signedMessage.readUInt32BE(sigLength + noncePosition),
      signer: DenoteUserIdentity.recoverUserID(signedMessage),
    };
  }

  /**
   * Recover an object
   * @static
   * @param {string} signedObj
   * @return {*}  {IRecoveredObject}
   * @memberof DenoteUserIdentity
   */
  public static recoverObject(signedObj: string): IRecoveredObject {
    const signedMessage = Buffer.from(signedObj, 'base64');
    return {
      obj: JSON.parse(signedMessage.slice(prefixLength + sigLength).toString()),
      nonce: signedMessage.readUInt32BE(sigLength + noncePosition),
      signer: DenoteUserIdentity.recoverUserID(signedMessage),
    };
  }

  /**
   * Create a new user
   * @static
   * @return {*}  {DenoteUserIdentity}
   * @memberof DenoteUserIdentity
   */
  public static createNewUser(): DenoteUserIdentity {
    return new DenoteUserIdentity(bip39.generateMnemonic());
  }

  /**
   * Restore user from a given mnemonic
   * @static
   * @param {string} mnemonic
   * @return {*}  {DenoteUserIdentity}
   * @memberof DenoteUserIdentity
   */
  public static fromMnemonic(mnemonic: string): DenoteUserIdentity {
    return new DenoteUserIdentity(mnemonic);
  }
}

export default DenoteUserIdentity;
