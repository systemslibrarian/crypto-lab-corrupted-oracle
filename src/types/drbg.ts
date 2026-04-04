export interface ECPoint {
  x: bigint;
  y: bigint;
}

export const POINT_AT_INFINITY: ECPoint = { x: 0n, y: 0n };

export interface DRBGState {
  algorithm: 'HMAC-DRBG' | 'ChaCha20-DRBG' | 'Dual-EC-DRBG';
  instantiated: boolean;
  reseedCounter: number;
  securityStrength: 128 | 192 | 256;
  internalState: Uint8Array;
}

export interface HMACDRBGInternalState {
  K: Uint8Array;
  V: Uint8Array;
}

export interface ChaCha20InternalState {
  key: Uint8Array;
  nonce: Uint8Array;
  counter: bigint;
}

export interface DualECInternalState {
  s: bigint;
}

export interface GenerateResult {
  bytes: Uint8Array;
  reseedRequired: boolean;
  reseedCounter: number;
}

export interface KATVector {
  id: string;
  securityStrength: number;
  entropyInput: string;
  nonce: string;
  personalization: string;
  entropyInputReseed: string;
  additionalInputReseed: string;
  additionalInput1: string;
  additionalInput2: string;
  returnedBits: string;
}

export interface KATResult {
  vectorId: string;
  passed: boolean;
  expected: string;
  actual: string;
  mismatchAt?: number;
}

export interface StatTestResult {
  name: string;
  pValue: number;
  passed: boolean;
  detail: string;
}

export interface AttackResult {
  success: boolean;
  recoveredState: bigint | null;
  candidatesTried: number;
  predictedOutputs: Uint8Array[];
  actualOutputs: Uint8Array[];
  match: boolean;
}

export interface AttackEvent {
  type: 'progress' | 'candidate_found' | 'state_recovered' | 'prediction';
  candidatesTried?: number;
  totalCandidates: number;
  recoveredState?: string;
  predictedOutput?: string;
  actualOutput?: string;
  match?: boolean;
}

export type AttackEventHandler = (event: AttackEvent) => void;
