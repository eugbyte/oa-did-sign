import { ethers } from "ethers";
import { Record, Static, String } from "runtypes";

export interface SigningOptions {
  signAsString?: boolean;
  signer?: ethers.Signer;
}

export const SigningKeyT = Record({
  private: String,
  public: String,
});

export type SigningKey = Static<typeof SigningKeyT>;

export type SigningFunction = (message: string, key: SigningKey, options?: SigningOptions) => Promise<string>;
