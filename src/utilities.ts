import { sha512, sha256 } from 'hash.js';

/**
 * Utilities
 * @export
 * @class Utilities
 */
export class Utilities {
  /**
   * Sha256 a given object
   * @static
   * @param {*} data
   * @return {*}  {string}
   * @memberof Utilities
   */
  public static sha256Object(data: any): string {
    return sha256().update(JSON.stringify(data)).digest('hex');
  }

  /**
   * Sha512 a given object
   * @static
   * @param {*} data
   * @return {*}  {string}
   * @memberof Utilities
   */
  public static sha512Object(data: any): string {
    return sha512().update(JSON.stringify(data)).digest('hex');
  }
}

export default Utilities;
