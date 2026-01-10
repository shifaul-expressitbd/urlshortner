// Centralized provider enum mapping utility
// This resolves the inconsistency between different provider mapping approaches
import { AuthProviderType } from 'prisma/generated/client';

export { AuthProviderType };

export const PROVIDER_MAPPING: Record<string, AuthProviderType> = {
  local: AuthProviderType.LOCAL,
  google: AuthProviderType.GOOGLE,
  facebook: AuthProviderType.FACEBOOK,
  github: AuthProviderType.GITHUB
};

export const REVERSE_PROVIDER_MAPPING: Record<AuthProviderType, string> = {
  [AuthProviderType.LOCAL]: 'local',
  [AuthProviderType.GOOGLE]: 'google',
  [AuthProviderType.FACEBOOK]: 'facebook',
  [AuthProviderType.GITHUB]: 'github'
};

/**
 * Maps a string provider name to the corresponding AuthProviderType enum
 * @param providerString - String representation of the provider
 * @returns The corresponding AuthProviderType enum
 * @throws Error if the provider is not supported
 */
export function mapStringToProviderEnum(providerString: string): AuthProviderType {
  const normalizedProvider = providerString.toLowerCase().trim();
  const enumValue = PROVIDER_MAPPING[normalizedProvider];
  
  if (!enumValue) {
    throw new Error(`Unsupported provider: ${providerString}. Supported providers: ${Object.keys(PROVIDER_MAPPING).join(', ')}`);
  }
  
  return enumValue;
}

/**
 * Maps an AuthProviderType enum to its string representation
 * @param provider - AuthProviderType enum value
 * @returns String representation of the provider
 */
export function mapProviderEnumToString(provider: AuthProviderType): string {
  const stringValue = REVERSE_PROVIDER_MAPPING[provider];
  
  if (!stringValue) {
    throw new Error(`Invalid AuthProviderType enum: ${provider}`);
  }
  
  return stringValue;
}

/**
 * Validates if a provider string is supported
 * @param providerString - String representation of the provider
 * @returns true if supported, false otherwise
 */
export function isSupportedProvider(providerString: string): boolean {
  try {
    mapStringToProviderEnum(providerString);
    return true;
  } catch {
    return false;
  }
}

/**
 * Gets all supported provider strings
 * @returns Array of supported provider strings
 */
export function getSupportedProviders(): string[] {
  return Object.keys(PROVIDER_MAPPING);
}

/**
 * Gets all supported AuthProviderType enum values
 * @returns Array of AuthProviderType enum values
 */
export function getSupportedProviderEnums(): AuthProviderType[] {
  return Object.values(AuthProviderType) as AuthProviderType[];
}
