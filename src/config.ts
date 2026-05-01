export interface WorkerEnv {
  JWKS_CACHE: KVNamespace;
  SUPABASE_URL: string;
  LOGIN_REDIRECT: string;
  UPGRADE_REDIRECT: string;
  WORKER_MODE: "shadow" | "enforce";
}
