import type { Check } from "../core/types.js";
import { supabaseKeyCheck } from "./supabaseKeys.js";
import {
  supabaseAuthSettingsCheck,
  supabaseGraphqlCheck,
  supabaseStorageCheck,
  supabaseTableCountCheck,
} from "./supabaseActive.js";
import {
  bundleSecretsCheck,
  securityHeadersCheck,
  sourceMapCheck,
  vercelOriginBypassCheck,
} from "./frontend.js";
import {
  corsCheck,
  exposedFilesCheck,
  renderOriginBypassCheck,
  stackTraceCheck,
} from "./render.js";

export const checks: Check[] = [
  supabaseKeyCheck,
  bundleSecretsCheck,
  sourceMapCheck,
  securityHeadersCheck,
  vercelOriginBypassCheck,
  exposedFilesCheck,
  stackTraceCheck,
  corsCheck,
  renderOriginBypassCheck,
  supabaseTableCountCheck,
  supabaseStorageCheck,
  supabaseAuthSettingsCheck,
  supabaseGraphqlCheck,
];
