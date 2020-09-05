import { Buffer } from 'safe-buffer';
interface IRecoveredObject {
    signer: string;
    obj: object;
}
export declare class DenoteUserIdentity {
    private mnemonic;
    private keyPair;
    private cachedUserID;
    constructor(mnemonic?: string);
    getMnemonic(): string;
    sign(message: Buffer): Buffer;
    signObject(obj: object): string;
    getUserID(): string;
    static publicKeyToUserID(pubKey: string | number[]): string;
    static recoverUserID(signedMessage: Buffer): string;
    static recoverObject(signedObj: string): IRecoveredObject;
    static createNewUser(): DenoteUserIdentity;
    static fromMnemonic(mnemonic: string): DenoteUserIdentity;
}
export default DenoteUserIdentity;
