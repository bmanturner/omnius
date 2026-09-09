import { GENERATED_AGAINST_CONTRACT_HASH } from "@omnius/web-sdk/client";

export interface WebBuildMetadata {
  readonly contractHash: string;
  readonly revision: string;
  readonly timestamp: string;
}

export const BUILD_METADATA: Readonly<WebBuildMetadata> = Object.freeze({
  contractHash: GENERATED_AGAINST_CONTRACT_HASH,
  revision: __BUILD_REVISION__,
  timestamp: __BUILD_TIMESTAMP__,
});
