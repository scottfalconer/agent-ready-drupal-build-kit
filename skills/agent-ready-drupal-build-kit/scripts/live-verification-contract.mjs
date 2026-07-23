export const LIVE_VERIFICATION_SCHEMA = 'public-kit.live-verification.2';
export const LIVE_VERIFICATION_MODE = 'live-target-and-packet';

export function createLiveVerificationReport(value = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Live verification report fields must be an object.');
  }
  const { schemaVersion: _ignoredSchemaVersion, ...report } = value;
  return {
    schemaVersion: LIVE_VERIFICATION_SCHEMA,
    ...report
  };
}

export function isCurrentLiveVerificationReport(value) {
  return value?.schemaVersion === LIVE_VERIFICATION_SCHEMA &&
    value?.verificationMode === LIVE_VERIFICATION_MODE;
}
