export interface SigningOptions {
  signAsString?: boolean;
}

export interface SigningKey {
  private: string;
  public: string;
}

export type SigningFunction = (message: string, key: SigningKey, options?: SigningOptions) => Promise<string>;
