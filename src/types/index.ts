export interface SigningOptions {
  signAsString?: boolean;
}

export type SigningFunction = (message: string, key: string, options?: SigningOptions) => Promise<string>;
