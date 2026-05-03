export interface WorkerEnv {
  JWKS_CACHE: KVNamespace;
  SUPABASE_URL: string;
  LOGIN_REDIRECT: string;
  UPGRADE_REDIRECT: string;
  WORKER_MODE: "shadow" | "enforce";
  // Base URL for the llmfixer-api backend that exposes `/v1/users/me`.
  // Round 6 / T6.1: the worker fetches name + subscription status here
  // and forwards them to LibreChat as `x-forwarded-name` and
  // `x-forwarded-subscription-status`.
  API_BASE_URL: string;
}
