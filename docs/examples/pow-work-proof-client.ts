/** Server-side reference client for the authenticated Actum work-proof admission API. */

export const ACTUM_WORK_PROOF_MEDIA_TYPE = "application/vnd.actum.work-proof.v1+json";
export const ACTUM_WORK_PROOF_PROFILE = "actum.non-overlap.risc0.v1";

export interface WorkProofAdmissionRequestV1 {
  schema: "actum.work-proof.admit.request.v1";
  operation: "verify_and_register";
  profile: "actum.non-overlap.risc0.v1";
  claim_id: string;
  public_claim_envelope_hex: string;
  proof_envelope_hex: string;
  anchor_request_envelope_hex: string;
  checkpointed_anchor_evidence_envelope_hex?: string | null;
}

export interface ExpectedWorkProofBindingsV1 {
  chain_id: string;
  project_id: string;
  policy_id: string;
  policy_revision: number;
}

export interface VerifiedWorkClaimV1 extends ExpectedWorkProofBindingsV1 {
  claim_id: string;
  lifecycle: "anchor_finalized";
  relation_verified: true;
  anchor_verified: true;
  usage_verified: true;
  idempotent: boolean;
  usage_domain: string;
  aggregate: Record<string, unknown>;
  anchor: {
    statement_id: string;
    finalized_height: number;
    finalized_block_id: string;
    checkpoint_bundle_id: string;
  };
  accepted_at_ms: number;
}

export interface WorkProofVerifierStatusV1 {
  status: "ready";
  chain_id: string;
  genesis_commitment: string;
  checkpoint_height: number;
  checkpoint_block_id: string;
  trust_bundle_id: string;
  trust_bundle_sequence: number;
  verifier_revision: number;
  proof_system_revision: number;
}

const DIGEST_384 = /^[0-9a-f]{96}$/;
const CANONICAL_HEX = /^(?:[0-9a-f]{2})+$/;
const REQUEST_KEYS = [
  "anchor_request_envelope_hex",
  "claim_id",
  "operation",
  "profile",
  "proof_envelope_hex",
  "public_claim_envelope_hex",
  "schema",
] as const;
const CLAIM_KEYS = [
  "accepted_at_ms",
  "aggregate",
  "anchor",
  "anchor_verified",
  "chain_id",
  "claim_id",
  "idempotent",
  "lifecycle",
  "policy_id",
  "policy_revision",
  "project_id",
  "relation_verified",
  "usage_domain",
  "usage_verified",
] as const;

const OPTIONAL_REQUEST_KEYS = ["checkpointed_anchor_evidence_envelope_hex"] as const;

function object(value: unknown, context: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${context} is not an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], context: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${context} has unsupported fields`);
  }
}

function exactKeysWithOptional(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  context: string,
): void {
  const actual = new Set(Object.keys(value));
  const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !actual.has(key)) || [...actual].some((key) => !allowed.has(key))) {
    throw new Error(`${context} has unsupported or missing fields`);
  }
}

function digest(value: unknown, context: string): string {
  if (typeof value !== "string" || !DIGEST_384.test(value)) {
    throw new Error(`${context} is not a canonical Digest384`);
  }
  return value;
}

function nonNegativeInteger(value: unknown, context: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new Error(`${context} is not a safe non-negative integer`);
  }
  return value as number;
}

function validateRequest(request: WorkProofAdmissionRequestV1): void {
  const value = object(request, "admission request");
  exactKeysWithOptional(value, REQUEST_KEYS, OPTIONAL_REQUEST_KEYS, "admission request");
  if (
    request.schema !== "actum.work-proof.admit.request.v1" ||
    request.operation !== "verify_and_register" ||
    request.profile !== ACTUM_WORK_PROOF_PROFILE
  ) {
    throw new Error("unsupported admission request profile");
  }
  digest(request.claim_id, "claim_id");
  for (const field of [
    "public_claim_envelope_hex",
    "proof_envelope_hex",
    "anchor_request_envelope_hex",
  ] as const) {
    if (!CANONICAL_HEX.test(request[field])) throw new Error(`${field} is not canonical lowercase hex`);
  }
  const checkpointedEvidence = request.checkpointed_anchor_evidence_envelope_hex;
  if (checkpointedEvidence !== undefined && checkpointedEvidence !== null && !CANONICAL_HEX.test(checkpointedEvidence)) {
    throw new Error("checkpointed_anchor_evidence_envelope_hex is not canonical lowercase hex");
  }
}

function validateClaim(
  input: unknown,
  request: WorkProofAdmissionRequestV1,
  expected: ExpectedWorkProofBindingsV1,
): VerifiedWorkClaimV1 {
  const claim = object(input, "verified claim");
  exactKeys(claim, CLAIM_KEYS, "verified claim");
  for (const field of ["claim_id", "chain_id", "project_id", "usage_domain", "policy_id"] as const) {
    digest(claim[field], field);
  }
  if (
    claim.claim_id !== request.claim_id ||
    claim.chain_id !== expected.chain_id ||
    claim.project_id !== expected.project_id ||
    claim.policy_id !== expected.policy_id ||
    claim.policy_revision !== expected.policy_revision
  ) {
    throw new Error("verified claim binding mismatch");
  }
  if (
    claim.lifecycle !== "anchor_finalized" ||
    claim.relation_verified !== true ||
    claim.anchor_verified !== true ||
    claim.usage_verified !== true ||
    typeof claim.idempotent !== "boolean"
  ) {
    throw new Error("stateful admission did not verify every required dimension");
  }
  object(claim.aggregate, "claim aggregate");
  const anchor = object(claim.anchor, "claim anchor");
  exactKeys(anchor, ["checkpoint_bundle_id", "finalized_block_id", "finalized_height", "statement_id"], "claim anchor");
  digest(anchor.statement_id, "anchor statement_id");
  digest(anchor.finalized_block_id, "anchor finalized_block_id");
  digest(anchor.checkpoint_bundle_id, "anchor checkpoint_bundle_id");
  nonNegativeInteger(anchor.finalized_height, "anchor finalized_height");
  nonNegativeInteger(claim.accepted_at_ms, "accepted_at_ms");
  return claim as unknown as VerifiedWorkClaimV1;
}

export class ActumWorkProofClient {
  readonly #baseUrl: URL;
  readonly #bearerToken: string;

  constructor(baseUrl: string, bearerToken: string) {
    this.#baseUrl = new URL(baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
    const local = ["127.0.0.1", "::1", "localhost"].includes(this.#baseUrl.hostname);
    if (this.#baseUrl.protocol !== "https:" && !(local && this.#baseUrl.protocol === "http:")) {
      throw new Error("work-proof verifier must use HTTPS outside local development");
    }
    if (!/^[\x21-\x7e]{32,256}$/.test(bearerToken)) throw new Error("invalid bearer token");
    this.#bearerToken = bearerToken;
  }

  async status(): Promise<WorkProofVerifierStatusV1> {
    const response = await this.#request("v1/status", { method: "GET" });
    const value = object(response, "verifier status");
    exactKeys(
      value,
      [
        "chain_id",
        "checkpoint_block_id",
        "checkpoint_height",
        "genesis_commitment",
        "proof_system_revision",
        "status",
        "trust_bundle_id",
        "trust_bundle_sequence",
        "verifier_revision",
      ],
      "verifier status",
    );
    if (value.status !== "ready") throw new Error("work-proof verifier is not ready");
    for (const field of ["chain_id", "genesis_commitment", "checkpoint_block_id", "trust_bundle_id"] as const) {
      digest(value[field], `status ${field}`);
    }
    for (const field of ["checkpoint_height", "trust_bundle_sequence", "verifier_revision", "proof_system_revision"] as const) {
      nonNegativeInteger(value[field], `status ${field}`);
    }
    return value as unknown as WorkProofVerifierStatusV1;
  }

  async verifyAndRegister(
    request: WorkProofAdmissionRequestV1,
    expected: ExpectedWorkProofBindingsV1,
  ): Promise<VerifiedWorkClaimV1> {
    validateRequest(request);
    for (const field of ["chain_id", "project_id", "policy_id"] as const) digest(expected[field], `expected ${field}`);
    nonNegativeInteger(expected.policy_revision, "expected policy_revision");
    const response = object(
      await this.#request("v1/proofs/verify", {
        method: "POST",
        headers: { "content-type": ACTUM_WORK_PROOF_MEDIA_TYPE },
        body: JSON.stringify(request),
      }),
      "admission response",
    );
    if (response.schema !== "actum.work-proof.admit.result.v1") throw new Error("unsupported admission response schema");
    if ("error" in response) {
      exactKeys(response, ["error", "schema"], "admission error");
      const error = object(response.error, "admission error body");
      exactKeys(error, ["code", "retryable"], "admission error body");
      throw new Error(`work-proof admission rejected: ${String(error.code)}`);
    }
    exactKeys(response, ["result", "schema"], "admission response");
    return validateClaim(response.result, request, expected);
  }

  async #request(path: string, init: RequestInit): Promise<unknown> {
    const response = await fetch(new URL(path, this.#baseUrl), {
      ...init,
      redirect: "error",
      headers: { ...init.headers, authorization: `Bearer ${this.#bearerToken}` },
    });
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > 65_536) throw new Error("work-proof response is oversized");
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      throw new Error("work-proof response is malformed");
    }
    if (!response.ok && !object(value, "work-proof error response").error) {
      throw new Error(`work-proof service failed with HTTP ${response.status}`);
    }
    return value;
  }
}
