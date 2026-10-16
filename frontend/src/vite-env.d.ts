/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_OFFICIAL_CHAIN_ID?: string;
  readonly VITE_VERIBIND_CONTRACT_ADDRESS?: string;
  readonly VITE_VERIBIND_DEPLOYMENT_BLOCK?: string;
  readonly VITE_DEMO_RECIPIENT_ADDRESS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
