import { Wallet, utils, ethers } from "ethers";
import { SigningFunction, SigningKey, SigningKeyT, SigningOptions } from "../../../types";

export const name = "Secp256k1VerificationKey2018";

export async function sign(message: string, key: SigningKey, options?: SigningOptions): Promise<string>;
export async function sign(message: string, signer: ethers.Signer, options?: SigningOptions): Promise<string>;

export async function sign(
  message: string,
  keyOrSigner: SigningKey | ethers.Signer,
  options: SigningOptions = {}
): Promise<string> {
  let signer: ethers.Signer;
  if (SigningKeyT.guard(keyOrSigner)) {
    const wallet = new Wallet(keyOrSigner.private);
    if (!keyOrSigner.public.toLowerCase().includes(wallet.address.toLowerCase())) {
      throw new Error(`Private key is wrong for ${keyOrSigner.public}`);
    }
    signer = wallet;
  } else if (keyOrSigner instanceof ethers.Signer) {
    signer = keyOrSigner;
  } else {
    throw new Error(`Either a keypair or ethers.js Signer must be provided`);
  }
  return signer.signMessage(options.signAsString ? message : utils.arrayify(message));
}
