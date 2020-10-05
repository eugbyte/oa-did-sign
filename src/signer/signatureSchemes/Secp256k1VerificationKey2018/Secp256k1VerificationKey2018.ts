import { Wallet, utils } from "ethers";
import { SigningFunction } from "../../../types";

export const name = "Secp256k1VerificationKey2018";

export const sign: SigningFunction = async (message: string, key: string, options = {}) => {
  const wallet = new Wallet(key);
  return wallet.signMessage(options.signAsString ? message : utils.arrayify(message));
};
