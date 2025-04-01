import { registerAuthenticationTools } from './authentication.js';
import { registerInjectionTools } from './injection.js';
import { registerDataLeakageTools } from './dataLeakage.js';
import { registerSecurityHeadersTools } from './securityHeaders.js';

/**
 * Register all security testing tools
 */
export function registerSecurityTools(server) {
  registerAuthenticationTools(server);
  registerInjectionTools(server);
  registerDataLeakageTools(server);
  registerSecurityHeadersTools(server);
}