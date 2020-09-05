"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DenoteUserIdentity = void 0;
const bs58_1 = __importDefault(require("bs58"));
const hash_js_1 = require("hash.js");
const elliptic_1 = require("elliptic");
const safe_buffer_1 = require("safe-buffer");
const bn_js_1 = __importDefault(require("bn.js"));
const bip39 = __importStar(require("bip39"));
const prefix = 'Denote User Identity {00000000}:\n';
const prefixLength = prefix.length;
const rLength = 32;
const sLength = 32;
const rsLength = rLength + sLength;
const vLength = 1;
const jLength = 1;
const sigLength = rLength + sLength + vLength + jLength;
class DenoteUserIdentity {
    constructor(mnemonic) {
        this.mnemonic = '';
        this.cachedUserID = '';
        this.mnemonic = mnemonic || bip39.generateMnemonic();
        const ec = new elliptic_1.ec('secp256k1');
        this.keyPair = ec.keyFromPrivate(hash_js_1.sha512().update(bip39.mnemonicToEntropy(this.mnemonic)).digest());
    }
    getMnemonic() {
        return this.mnemonic;
    }
    sign(message) {
        const ec = new elliptic_1.ec('secp256k1');
        const vj = safe_buffer_1.Buffer.alloc(2);
        const prefixedMessage = safe_buffer_1.Buffer.allocUnsafe(message.length + prefixLength);
        prefixedMessage.write(prefix, 0);
        prefixedMessage.writeUInt32BE(((Date.now() / 1000) & 0xffffffff) >>> 0, 26);
        message.copy(prefixedMessage, prefixLength);
        const messageDigest = hash_js_1.sha256().update(prefixedMessage).digest();
        const signature = this.keyPair.sign(messageDigest);
        const qPrime = new bn_js_1.default(this.keyPair.getPublic().encode('hex', false), 'hex', 'be');
        vj.writeUInt8(signature.recoveryParam || 0, 0);
        vj.writeUInt8(ec.getKeyRecoveryParam(undefined, signature, qPrime), 1);
        return safe_buffer_1.Buffer.concat([
            safe_buffer_1.Buffer.from(signature.r.toArray('be')),
            safe_buffer_1.Buffer.from(signature.s.toArray('be')),
            vj,
            prefixedMessage,
        ]);
    }
    signObject(obj) {
        return this.sign(safe_buffer_1.Buffer.from(JSON.stringify(obj))).toString('base64');
    }
    getUserID() {
        if (this.cachedUserID.length > 0) {
            return this.cachedUserID;
        }
        if (typeof this.keyPair !== 'undefined') {
            this.cachedUserID = DenoteUserIdentity.publicKeyToUserID(this.keyPair.getPublic().encode('array', false));
            return this.cachedUserID;
        }
        throw new Error('Key pair is undefined can not get ID');
    }
    static publicKeyToUserID(pubKey) {
        let pubKeyDigest;
        if (typeof pubKey === 'string') {
            pubKeyDigest = hash_js_1.ripemd160().update(pubKey, 'hex').digest();
        }
        else {
            pubKeyDigest = hash_js_1.ripemd160().update(pubKey).digest();
        }
        return bs58_1.default.encode(pubKeyDigest);
    }
    static recoverUserID(signedMessage) {
        const ec = new elliptic_1.ec('secp256k1');
        const r = new bn_js_1.default(signedMessage.slice(0, rLength).toString('hex'), 'hex', 'be');
        const s = new bn_js_1.default(signedMessage.slice(rLength, rsLength).toString('hex'), 'hex', 'be');
        const recoveryParam = signedMessage.readUInt8(rsLength);
        const j = signedMessage.readUInt8(rsLength + vLength);
        const message = signedMessage.slice(sigLength);
        const messageDigest = hash_js_1.sha256().update(message).digest();
        const pubKey = ec.recoverPubKey(messageDigest, {
            r,
            s,
            recoveryParam,
        }, j);
        return DenoteUserIdentity.publicKeyToUserID(pubKey.encode('hex', false));
    }
    static recoverObject(signedObj) {
        const signedMessage = safe_buffer_1.Buffer.from(signedObj, 'base64');
        return {
            obj: JSON.parse(signedMessage.slice(prefixLength + sigLength).toString()),
            signer: DenoteUserIdentity.recoverUserID(signedMessage),
        };
    }
    static createNewUser() {
        return new DenoteUserIdentity(bip39.generateMnemonic());
    }
    static fromMnemonic(mnemonic) {
        return new DenoteUserIdentity(mnemonic);
    }
}
exports.DenoteUserIdentity = DenoteUserIdentity;
exports.default = DenoteUserIdentity;
