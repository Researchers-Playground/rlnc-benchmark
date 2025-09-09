use super::scalar::Scalar;
use crate::commitments::{CodedPiece, Committer};
use crate::utils::blst::coefficients_to_scalars;
use rayon::prelude::*;
use serde_json;
// Removed global caching to avoid KzgSettings export issues
use sha2::{Digest, Sha256};
use thiserror::Error;

// Import kzg_rust types and functions
use kzg_rust::{Blob, Bytes32, Kzg, KzgCommitment, KzgProof, KzgSettings, BYTES_PER_BLOB};

// Additional verification data variants
#[derive(Clone, Debug)]
pub enum KzgAdditional {
    // Single-point openings: each point has an individual proof
    Single {
        points: Vec<Scalar>,
        proofs: Vec<KzgProof>,
        alpha_seed: [u8; 32],
    },
    // Multi-open (vanishing): many points aggregated into one proof
    Multi {
        points: Vec<Scalar>,
        proof: KzgProof,
        alpha_seed: [u8; 32],
    },
}

// Verify-time inputs for a coded piece
// Supports single or multiple points by using vectors
// Backward-compatible alias for older call sites (not used now)
pub type KzgVerifyData = KzgAdditional;

#[derive(Error, Debug)]
pub enum KzgError {
    #[error("Invalid chunk size: expected max {expected}, got {actual}")]
    InvalidChunkSize { expected: usize, actual: usize },
    #[error("Commitment failed: {0}")]
    CommitFailed(String),
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Setup verification failed")]
    SetupVerificationFailed,
    #[error("Pairing check failed")]
    PairingCheckFailed,
    #[error("Invalid polynomial degree: {0}")]
    InvalidDegree(String),
    #[error("KZG setup error: {0}")]
    SetupError(String),
    #[error("Conversion error: {0}")]
    ConversionError(String),
    #[error("KZG library error: {0}")]
    KzgLibError(String),
    #[error("Commitment binding attack detected: {0}")]
    CommitmentBindingAttack(String),
}

// We create the KZG settings inline in each function
// since the library doesn't export KzgSettings publicly

/// Convert scalars to blob bytes (pad or truncate to BYTES_PER_BLOB) - Parallel optimized
fn scalar_to_le32(x: &Scalar) -> [u8; 32] {
    let mut b = x.to_bytes();
    b.reverse();
    b
}

fn bytes32_from_scalar_be(x: &Scalar) -> Result<Bytes32, KzgError> {
    Bytes32::from_bytes(&x.to_bytes()).map_err(|e| {
        KzgError::ConversionError(format!("Failed to convert scalar (BE) to Bytes32: {:?}", e))
    })
}

fn scalars_to_blob(scalars: &[Scalar]) -> Result<Blob, KzgError> {
    const ELS: usize = BYTES_PER_BLOB / 32;
    if scalars.len() > ELS {
        return Err(KzgError::InvalidChunkSize {
            expected: ELS,
            actual: scalars.len(),
        });
    }
    let mut blob_bytes = [0u8; BYTES_PER_BLOB];
    for (i, s) in scalars.iter().enumerate() {
        // Canonicalize to field element bytes (BE) via blst_fr
        let fr = s.to_blst_fr();
        let can = Scalar::from_blst_fr(&fr);
        let be = can.to_bytes();
        blob_bytes[i * 32..(i + 1) * 32].copy_from_slice(&be);
    }
    Blob::from_bytes(&blob_bytes)
        .map_err(|e| KzgError::ConversionError(format!("Failed to create blob: {:?}", e)))
}

/// KZG Commitment parameters using kzg_rust
#[derive(Clone, Debug)]
pub struct KzgParams {
    /// G1 points for trusted setup
    g1_points: Vec<[u8; 48]>,
    /// G2 points for trusted setup  
    g2_points: Vec<[u8; 96]>,
}

impl KzgParams {
    /// Load trusted setup from embedded data (for testing)
    /// WARNING: This uses a test setup and is NOT cryptographically secure for production!
    pub fn new_insecure() -> Result<Self, KzgError> {
        // Load trusted setup from https://github.com/perfogic/kzg_rust/blob/master/testing_trusted_setups.json
        let trusted_setup_json = include_str!("../../../trusted-setup.json");

        // Parse the JSON to extract G1 and G2 points
        let value: serde_json::Value = serde_json::from_str(trusted_setup_json)
            .map_err(|e| KzgError::SetupError(format!("Failed to parse trusted setup: {}", e)))?;

        let setup_g1 = value["setup_G1_lagrange"]
            .as_array()
            .ok_or_else(|| KzgError::SetupError("Missing setup_G1_lagrange".to_string()))?;

        let setup_g2 = value["setup_G2"]
            .as_array()
            .ok_or_else(|| KzgError::SetupError("Missing setup_G2".to_string()))?;

        // Convert G1 points from hex strings to byte arrays
        let mut g1_points = Vec::with_capacity(setup_g1.len());
        for point_str in setup_g1 {
            let hex_str = point_str
                .as_str()
                .ok_or_else(|| KzgError::SetupError("Invalid G1 point format".to_string()))?;

            let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
                .map_err(|e| KzgError::SetupError(format!("Failed to decode G1 point: {}", e)))?;

            if bytes.len() != 48 {
                return Err(KzgError::SetupError(format!(
                    "Invalid G1 point length: expected 48, got {}",
                    bytes.len()
                )));
            }

            let mut point = [0u8; 48];
            point.copy_from_slice(&bytes);
            g1_points.push(point);
        }

        // Convert G2 points from hex strings to byte arrays
        let mut g2_points = Vec::with_capacity(setup_g2.len());
        for point_str in setup_g2 {
            let hex_str = point_str
                .as_str()
                .ok_or_else(|| KzgError::SetupError("Invalid G2 point format".to_string()))?;

            let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
                .map_err(|e| KzgError::SetupError(format!("Failed to decode G2 point: {}", e)))?;

            if bytes.len() != 96 {
                return Err(KzgError::SetupError(format!(
                    "Invalid G2 point length: expected 96, got {}",
                    bytes.len()
                )));
            }

            let mut point = [0u8; 96];
            point.copy_from_slice(&bytes);
            g2_points.push(point);
        }

        Ok(KzgParams {
            g1_points,
            g2_points,
        })
    }

    /// Load trusted setup from points
    pub fn from_points(g1_points: Vec<[u8; 48]>, g2_points: Vec<[u8; 96]>) -> Self {
        KzgParams {
            g1_points,
            g2_points,
        }
    }

    /// Verify that the setup is well-formed
    pub fn verify_setup(&self) -> Result<(), KzgError> {
        // Basic sanity checks
        if self.g1_points.len() < 2 || self.g2_points.len() < 2 {
            return Err(KzgError::SetupVerificationFailed);
        }
        Ok(())
    }
}

/// KZG Polynomial Commitment Scheme using kzg_rust
#[derive(Clone)]
pub struct KzgCommitter {
    params: KzgParams,
}

impl KzgCommitter {
    /// Create a new KZG committer with the given parameters
    pub fn new(params: KzgParams) -> Self {
        Self { params }
    }

    /// Create a new KZG committer with insecure setup (for testing only)
    pub fn new_insecure() -> Result<Self, KzgError> {
        let params = KzgParams::new_insecure()?;
        Ok(Self::new(params))
    }

    /// Commit to a polynomial represented by its coefficients
    pub fn commit_polynomial(&self, coefficients: &[Scalar]) -> Result<KzgCommitment, KzgError> {
        if coefficients.is_empty() {
            return Err(KzgError::CommitFailed("Empty polynomial".to_string()));
        }

        // Convert scalars to blob format
        let blob = scalars_to_blob(coefficients)?;

        // Create KZG settings from our parameters
        let settings = Kzg::load_trusted_setup(
            self.params.g1_points.clone(),
            self.params.g2_points.clone(),
        )
        .map_err(|e| KzgError::SetupError(format!("Failed to create KZG settings: {:?}", e)))?;

        let commitment = Kzg::blob_to_kzg_commitment(&blob, &settings)
            .map_err(|e| KzgError::CommitFailed(format!("Commitment failed: {:?}", e)))?;

        Ok(commitment)
    }

    /// Generate a KZG proof that polynomial p(x) has value y at point z
    pub fn create_proof(
        &self,
        polynomial: &[Scalar],
        z: Scalar,
    ) -> Result<(KzgProof, Scalar), KzgError> {
        if polynomial.is_empty() {
            return Err(KzgError::CommitFailed("Empty polynomial".to_string()));
        }

        // Convert scalars to blob format
        let blob = scalars_to_blob(polynomial)?;

        // Convert z to bytes (32 bytes for field element)
        let z_bytes = bytes32_from_scalar_be(&z)?;

        // Create KZG settings from our parameters
        let settings = Kzg::load_trusted_setup(
            self.params.g1_points.clone(),
            self.params.g2_points.clone(),
        )
        .map_err(|e| KzgError::SetupError(format!("Failed to create KZG settings: {:?}", e)))?;

        let (proof, y_bytes) = Kzg::compute_kzg_proof(&blob, &z_bytes, &settings)
            .map_err(|e| KzgError::CommitFailed(format!("Proof creation failed: {:?}", e)))?;

        // Convert y_bytes back to scalar (assume BE from kzg_rust)
        let y = Scalar::from_bytes(&*y_bytes).map_err(|e| {
            KzgError::ConversionError(format!("Failed to convert y to scalar: {:?}", e))
        })?;

        Ok((proof, y))
    }

    /// Verify a KZG proof
    pub fn verify_proof(
        &self,
        commitment: &KzgCommitment,
        z: Scalar,
        y: Scalar,
        proof: &KzgProof,
    ) -> Result<bool, KzgError> {
        let z_bytes = bytes32_from_scalar_be(&z)?;
        let y_bytes = bytes32_from_scalar_be(&y)?;

        // Create KZG settings from our parameters
        let settings = Kzg::load_trusted_setup(
            self.params.g1_points.clone(),
            self.params.g2_points.clone(),
        )
        .map_err(|e| KzgError::SetupError(format!("Failed to create KZG settings: {:?}", e)))?;

        let result = Kzg::verify_kzg_proof(commitment, &z_bytes, &y_bytes, proof, &settings)
            .map_err(|_e| KzgError::PairingCheckFailed)?;

        Ok(result)
    }

    /// Batch verify multiple proofs (if supported by underlying library)
    pub fn batch_verify_blob_proofs(
        &self,
        blobs: &[Blob],
        commitments: &[KzgCommitment],
        proofs: &[KzgProof],
    ) -> Result<bool, KzgError> {
        if blobs.len() != commitments.len() || commitments.len() != proofs.len() {
            return Err(KzgError::InvalidChunkSize {
                expected: blobs.len(),
                actual: proofs.len(),
            });
        }

        // Create KZG settings from our parameters
        let settings = Kzg::load_trusted_setup(
            self.params.g1_points.clone(),
            self.params.g2_points.clone(),
        )
        .map_err(|e| KzgError::SetupError(format!("Failed to create KZG settings: {:?}", e)))?;

        let result = Kzg::verify_blob_kzg_proof_batch(blobs, commitments, proofs, &settings)
            .map_err(|_e| KzgError::PairingCheckFailed)?;

        Ok(result)
    }

    /// Generate KZG proofs for multiple points on the same polynomial
    pub fn create_batch_proofs(
        &self,
        polynomial: &[Scalar],
        points: &[Scalar],
    ) -> Result<Vec<(KzgProof, Scalar)>, KzgError> {
        if polynomial.is_empty() {
            return Err(KzgError::CommitFailed("Empty polynomial".to_string()));
        }

        // Convert polynomial to blob once
        let blob = scalars_to_blob(polynomial)?;

        // Create KZG settings from our parameters
        let settings = Kzg::load_trusted_setup(
            self.params.g1_points.clone(),
            self.params.g2_points.clone(),
        )
        .map_err(|e| KzgError::SetupError(format!("Failed to create KZG settings: {:?}", e)))?;

        // Parallel proof generation for better performance
        let proofs: Result<Vec<(KzgProof, Scalar)>, KzgError> = points
            .par_iter()
            .map(|&z| {
                let z_bytes = bytes32_from_scalar_be(&z)?;

                let (proof, y_bytes) =
                    Kzg::compute_kzg_proof(&blob, &z_bytes, &settings).map_err(|e| {
                        KzgError::CommitFailed(format!("Proof creation failed: {:?}", e))
                    })?;

                let y = Scalar::from_bytes(&*y_bytes).map_err(|e| {
                    KzgError::ConversionError(format!("Failed to convert y to scalar: {:?}", e))
                })?;

                Ok((proof, y))
            })
            .collect();

        let proofs = proofs?;

        Ok(proofs)
    }

    /// Create a single multiproof for multiple points using kzg_rust's multi-KZG API.
    /// Returns (proof, ys) where ys are evaluations at the provided points.
    pub fn create_multi_point_proof(
        &self,
        polynomial: &[Scalar],
        points: &[Scalar],
    ) -> Result<(KzgProof, Vec<Scalar>), KzgError> {
        if polynomial.is_empty() {
            return Err(KzgError::CommitFailed("Empty polynomial".to_string()));
        }

        // Convert polynomial to blob once
        let blob = scalars_to_blob(polynomial)?;

        // Settings
        let settings = Kzg::load_trusted_setup(
            self.params.g1_points.clone(),
            self.params.g2_points.clone(),
        )
        .map_err(|e| KzgError::SetupError(format!("Failed to create KZG settings: {:?}", e)))?;

        // Convert points to Bytes32 (BE)
        let zs: Result<Vec<Bytes32>, _> =
            points.iter().map(|z| bytes32_from_scalar_be(z)).collect();
        let zs = zs?;

        // Compute multi-proof and y values
        let (proof, ys_bytes) = Kzg::compute_multi_kzg_proof(&blob, &zs, &settings)
            .map_err(|e| KzgError::CommitFailed(format!("Multi-proof creation failed: {:?}", e)))?;

        // Convert ys back to Scalar (BE)
        let ys: Result<Vec<Scalar>, _> = ys_bytes
            .iter()
            .map(|b| {
                Scalar::from_bytes(&b[..])
                    .map_err(|e| KzgError::ConversionError(format!("y parse error: {:?}", e)))
            })
            .collect();
        let ys = ys?;

        Ok((proof, ys))
    }

    /// Create a single aggregated proof for multiple points via vanishing technique.
    /// Returns (proof_at_r, r), where r is a Fiat–Shamir challenge derived from transcript.
    pub fn create_multiopen_proof(
        &self,
        polynomial: &[Scalar],
        points: &[Scalar],
        values: &[Scalar],
        coded_commitment: &KzgCommitment,
    ) -> Result<(KzgProof, Scalar), KzgError> {
        if points.len() != values.len() {
            return Err(KzgError::CommitFailed("points/values mismatch".into()));
        }
        if polynomial.is_empty() {
            return Err(KzgError::CommitFailed("Empty polynomial".into()));
        }

        let r = derive_challenge_r(coded_commitment, points, values);
        // Convert polynomial to blob once
        let blob = scalars_to_blob(polynomial)?;
        // Settings
        let settings = Kzg::load_trusted_setup(
            self.params.g1_points.clone(),
            self.params.g2_points.clone(),
        )
        .map_err(|e| KzgError::SetupError(format!("Failed to create KZG settings: {:?}", e)))?;

        let r_bytes = bytes32_from_scalar_be(&r)?;
        let (proof, _y_bytes) = Kzg::compute_kzg_proof(&blob, &r_bytes, &settings)
            .map_err(|e| KzgError::CommitFailed(format!("Proof creation failed: {:?}", e)))?;

        Ok((proof, r))
    }

    /// Verify multiple proofs for the same commitment - Parallel optimized
    pub fn verify_batch_proofs(
        &self,
        commitment: &KzgCommitment,
        points_and_proofs: &[(Scalar, Scalar, KzgProof)], // (z, y, proof)
    ) -> Result<bool, KzgError> {
        // Create KZG settings from our parameters
        let settings = Kzg::load_trusted_setup(
            self.params.g1_points.clone(),
            self.params.g2_points.clone(),
        )
        .map_err(|e| KzgError::SetupError(format!("Failed to create KZG settings: {:?}", e)))?;

        // Parallel verification for better performance
        let results: Result<Vec<bool>, KzgError> = points_and_proofs
            .par_iter()
            .map(|&(z, y, ref proof)| {
                let z_bytes = bytes32_from_scalar_be(&z)?;
                let y_bytes = bytes32_from_scalar_be(&y)?;

                let is_valid =
                    Kzg::verify_kzg_proof(commitment, &z_bytes, &y_bytes, proof, &settings)
                        .map_err(|_e| KzgError::PairingCheckFailed)?;

                Ok(is_valid)
            })
            .collect();

        let results = results?;
        // Return true only if ALL verifications pass
        Ok(results.iter().all(|&valid| valid))
    }

    /// Create column commitments (Danksharding style)
    /// One commitment per column, stored in block header
    pub fn create_column_commitments(
        &self,
        column_data: &[Vec<Scalar>], // Each column as a polynomial
    ) -> Result<Vec<KzgCommitment>, KzgError> {
        column_data
            .iter()
            .map(|column| self.commit_polynomial(column))
            .collect()
    }

    /// Get access to the parameters (for advanced usage)
    pub fn params(&self) -> &KzgParams {
        &self.params
    }
}

impl Committer for KzgCommitter {
    type Scalar = Scalar;
    type Commitment = Vec<KzgCommitment>;
    type Error = KzgError;
    type AdditionalData = KzgAdditional;

    fn commit(&self, chunks: &Vec<Vec<Self::Scalar>>) -> Result<Self::Commitment, Self::Error> {
        chunks
            .iter()
            .map(|chunk| self.commit_polynomial(chunk))
            .collect()
    }

    fn verify(
        &self,
        commitment: Option<&Self::Commitment>,
        piece: &CodedPiece<Self::Scalar>,
        additional_data: Option<&Self::AdditionalData>,
    ) -> bool {
        // Need commitments and additional verification data
        let (commitments, ad) = match (commitment, additional_data) {
            (Some(c), Some(ad)) => (c, ad),
            _ => return false,
        };
        match ad {
            KzgAdditional::Single {
                points,
                proofs,
                alpha_seed,
            } => {
                // Derive α from seed
                let alphas: Vec<Scalar> =
                    coefficients_to_scalars(&expand_to_field(alpha_seed, commitments.len()));
                // Compute coded commitment C*
                let coded_commitment = match msm_g1(commitments, &alphas) {
                    Ok(c) => c,
                    Err(_) => return false,
                };
                if piece.data.len() != points.len() || points.len() != proofs.len() {
                    return false;
                }
                let settings = match Kzg::load_trusted_setup(
                    self.params.g1_points.clone(),
                    self.params.g2_points.clone(),
                ) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                for ((z, y), proof) in points.iter().zip(piece.data.iter()).zip(proofs.iter()) {
                    let z_bytes = match bytes32_from_scalar_be(z) {
                        Ok(b) => b,
                        Err(_) => return false,
                    };
                    let y_bytes = match bytes32_from_scalar_be(y) {
                        Ok(b) => b,
                        Err(_) => return false,
                    };
                    let ok = Kzg::verify_kzg_proof(
                        &coded_commitment,
                        &z_bytes,
                        &y_bytes,
                        proof,
                        &settings,
                    )
                    .unwrap_or(false);
                    if !ok {
                        return false;
                    }
                }
                true
            }
            KzgAdditional::Multi {
                points,
                proof,
                alpha_seed,
            } => {
                // Derive α from seed and compute coded commitment
                let alphas: Vec<Scalar> =
                    coefficients_to_scalars(&expand_to_field(alpha_seed, commitments.len()));
                let coded_commitment = match msm_g1(commitments, &alphas) {
                    Ok(c) => c,
                    Err(_) => return false,
                };
                if piece.data.len() != points.len() {
                    return false;
                }
                // Convert zs and ys to Bytes32 (BE)
                let zs: Result<Vec<Bytes32>, _> =
                    points.iter().map(|z| bytes32_from_scalar_be(z)).collect();
                let ys: Result<Vec<Bytes32>, _> = piece
                    .data
                    .iter()
                    .map(|y| bytes32_from_scalar_be(y))
                    .collect();
                let (zs, ys) = match (zs, ys) {
                    (Ok(z), Ok(y)) => (z, y),
                    _ => return false,
                };
                // Settings
                let settings = match Kzg::load_trusted_setup(
                    self.params.g1_points.clone(),
                    self.params.g2_points.clone(),
                ) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                Kzg::verify_multi_kzg_proof(&coded_commitment, &zs, &ys, &proof, &settings)
                    .unwrap_or(false)
            }
        }
    }
}

// Multi-scalar multiplication in G1 to combine commitments with coefficients
fn msm_g1(commits: &[KzgCommitment], coeffs: &[Scalar]) -> Result<KzgCommitment, KzgError> {
    use blst::{blst_p1, blst_p1_affine, blst_scalar, BLST_ERROR};

    if commits.len() != coeffs.len() {
        return Err(KzgError::ConversionError(
            "Length mismatch in MSM inputs".to_string(),
        ));
    }
    if commits.is_empty() {
        return Err(KzgError::ConversionError("Empty input for MSM".to_string()));
    }

    let mut result_point = blst_p1::default();
    let mut first = true;

    for (commit, coeff) in commits.iter().zip(coeffs.iter()) {
        // Decompress commitment to affine point
        let mut affine_point = blst_p1_affine::default();
        let decompress_result =
            unsafe { blst::blst_p1_uncompress(&mut affine_point, commit.as_ptr()) };
        if decompress_result != BLST_ERROR::BLST_SUCCESS {
            return Err(KzgError::ConversionError(format!(
                "Failed to decompress G1 point: {:?}",
                decompress_result
            )));
        }

        // Subgroup check
        let in_g1 = unsafe { blst::blst_p1_affine_in_g1(&affine_point) };
        if !in_g1 {
            return Err(KzgError::ConversionError(
                "Commitment point not in G1 subgroup".to_string(),
            ));
        }

        // To projective
        let mut projective_point = blst_p1::default();
        unsafe { blst::blst_p1_from_affine(&mut projective_point, &affine_point) };

        // Scalar to blst format
        let mut blst_scalar_val = blst_scalar::default();
        let fr = coeff.to_blst_fr();
        unsafe { blst::blst_scalar_from_fr(&mut blst_scalar_val, &fr) };

        // Multiply point by scalar
        let mut scaled_point = blst_p1::default();
        unsafe {
            blst::blst_p1_mult(
                &mut scaled_point,
                &projective_point,
                blst_scalar_val.b.as_ptr(),
                255,
            )
        };

        // Accumulate
        if first {
            result_point = scaled_point;
            first = false;
        } else {
            unsafe { blst::blst_p1_add(&mut result_point, &result_point, &scaled_point) };
        }
    }

    // Compress back to 48-byte commitment
    let mut compressed = [0u8; 48];
    unsafe { blst::blst_p1_compress(compressed.as_mut_ptr(), &result_point) };
    Ok(KzgCommitment::from(compressed))
}

// Expand a 32-byte seed into n field elements deterministically (via SHA-256 counter mode)
fn expand_to_field(seed: &[u8; 32], n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(seed);
            h.update(&(i as u32).to_le_bytes());
            let out = h.finalize();
            let val = u128::from_le_bytes(out[..16].try_into().unwrap()); // hoặc dùng u256 nếu bạn có lib hỗ trợ
            let small = (val % 128) as u8;
            small
        })
        .collect()
}

// Lagrange interpolation evaluation at point r: sum_i y_i * l_i(r)
fn lagrange_eval_at(points: &[Scalar], values: &[Scalar], r: Scalar) -> Result<Scalar, KzgError> {
    if points.len() != values.len() {
        return Err(KzgError::CommitFailed("points/values mismatch".into()));
    }
    let m = points.len();
    if m == 0 {
        return Err(KzgError::CommitFailed("empty points".into()));
    }
    let mut acc = Scalar::from(0u32);
    for i in 0..m {
        let mut num = Scalar::from(1u32);
        let mut den = Scalar::from(1u32);
        for j in 0..m {
            if i == j {
                continue;
            }
            num = num * (r - points[j]);
            den = den * (points[i] - points[j]);
        }
        let den_inv = den.inverse().ok_or_else(|| {
            KzgError::CommitFailed("Non-invertible denominator (duplicate points?)".into())
        })?;
        let li = num * den_inv;
        acc = acc + (values[i] * li);
    }
    Ok(acc)
}

// Fiat–Shamir to derive aggregation challenge r
fn derive_challenge_r(commitment: &KzgCommitment, points: &[Scalar], values: &[Scalar]) -> Scalar {
    let mut h = Sha256::new();
    h.update(b"rlnc-kzg-multi-v1");
    h.update(commitment.as_ref());
    for z in points.iter() {
        h.update(z.to_bytes());
    }
    for y in values.iter() {
        h.update(y.to_bytes());
    }
    let bytes = h.finalize();
    // Canonicalize to Fr
    let s = Scalar::from_bytes(&bytes).unwrap();
    let fr = s.to_blst_fr();
    Scalar::from_blst_fr(&fr)
}

#[cfg(test)]
mod tests {
    use crate::utils::blst::coefficients_to_scalars;

    use super::*;
    use rand::RngCore;
    use rayon::prelude::*;
    use sha2::Sha256;

    // Reduce any scalar to its canonical field representation
    fn canonicalize(s: &Scalar) -> Scalar {
        let fr = s.to_blst_fr();
        Scalar::from_blst_fr(&fr)
    }

    // Derive z from transcript (public): z = H(domain || row || col) reduced to Fr
    fn derive_point(row: u8, col: u8) -> Scalar {
        let mut h = Sha256::new();
        h.update(b"rlnc-kzg-z-v1");
        h.update([row, col]);
        let bytes = h.finalize();
        let s = Scalar::from_bytes(&bytes).unwrap();
        canonicalize(&s)
    }

    // Packet: single-point (α bytes, y, proof, j)
    #[derive(Clone, Debug)]
    struct CodedPiecePacketSingle {
        coefficients: Vec<u8>,
        y: Scalar,
        proof: KzgProof,
        row: u8,
        col: u8,
    }

    // Packet: multi-point (α bytes, [y], [proof], [j])
    #[derive(Clone, Debug)]
    struct CodedPiecePacketMulti {
        coefficients: Vec<u8>,
        ys: Vec<Scalar>,
        proofs: Vec<KzgProof>,
    }

    #[test]
    fn rlnc_kzg_end_to_end() {
        println!("=== RLNC + KZG Commitment Test ===");

        // 1. Setup KZG committer
        let committer = KzgCommitter::new_insecure().unwrap();

        // 2. Create n=32 column data B_i (following spec: B_i = [b_i1, b_i2, ..., b_iL])
        let n = 32;
        let l = 64;
        let column_data: Vec<Vec<Scalar>> = (0..n)
            .map(|i| {
                (0..l)
                    .map(|j| Scalar::from((i * l + j + 1) as u32))
                    .collect()
            })
            .collect();

        // 3. Polynomial mapping: Each B_i -> f_i(X) and commit C_i = Commit(f_i)
        let column_commitments = committer.create_column_commitments(&column_data).unwrap();
        println!("✓ Created {} column commitments", column_commitments.len());

        // 4. Generate coding vector α = (α_1, ..., α_n) from VRF/commit
        let row_id: u8 = 7;
        let cell_idx: u8 = 13;
        let mut hasher = Sha256::new();
        hasher.update(b"rlnc-kzg-alpha-v1");
        hasher.update(&[row_id, cell_idx]);
        let hash = hasher.finalize();

        let mut alpha_seed = [0u8; 32];
        alpha_seed.copy_from_slice(&hash);
        let alpha_coeffs: Vec<Scalar> = coefficients_to_scalars(&expand_to_field(&alpha_seed, n));
        println!(
            "✓ Generated coding vector α of length {}",
            alpha_coeffs.len()
        );

        // 5. Compute coded polynomial F*(X) = Σ α_i * f_i(X)
        let mut coded_polynomial = vec![Scalar::from(0u32); l];
        for (f_i, &alpha_i) in column_data.iter().zip(alpha_coeffs.iter()) {
            for (j, &coeff) in f_i.iter().enumerate() {
                coded_polynomial[j] = coded_polynomial[j] + (alpha_i * coeff);
            }
        }

        // 6. Compute coded commitment C* = Σ α_i * C_i using MSM
        let coded_commitment = msm_g1(&column_commitments, &alpha_coeffs).unwrap();
        println!("✓ Computed coded commitment C* using MSM");

        // 7. Evaluation point: derive from transcript
        let x_j = derive_point(row_id, cell_idx);

        // 8. Create proof that y_j = F*(x_j)
        let (proof, y_j) = committer.create_proof(&coded_polynomial, x_j).unwrap();

        // Build a single-point packet for sending: (α bytes, y, proof, j)
        let packet_single = CodedPiecePacketSingle {
            coefficients: hash[..n].to_vec(),
            y: y_j,
            proof: proof.clone(),
            row: row_id,
            col: cell_idx,
        };

        // Receiver reconstructs z from j and verifies using trait API
        let recv_z = derive_point(packet_single.row, packet_single.col);
        let piece = CodedPiece {
            coefficients: packet_single.coefficients.clone(),
            data: vec![packet_single.y],
        };
        let ad = KzgAdditional::Single {
            points: vec![recv_z],
            proofs: vec![packet_single.proof.clone()],
            alpha_seed,
        };
        assert!(committer.verify(Some(&column_commitments), &piece, Some(&ad)));
        println!(
            "✓ Created KZG proof for coded value y_j = {}",
            y_j.to_bytes()[0]
        );

        // === VERIFICATION TESTS ===

        // Test 1: Valid verification should pass
        assert!(committer
            .verify_proof(&coded_commitment, x_j, y_j, &proof)
            .unwrap());
        println!("✅ Test 1: Valid proof verification passed");

        // Test 2: Attack with wrong coded value should fail
        let y_attack = y_j + Scalar::from(1u32);
        assert!(!committer
            .verify_proof(&coded_commitment, x_j, y_attack, &proof)
            .unwrap_or(false));
        println!("✅ Test 2: Wrong coded value attack blocked");

        // Test 3: Attack with wrong evaluation point should fail
        let x_attack = x_j + Scalar::from(1u32);
        assert!(!committer
            .verify_proof(&coded_commitment, x_attack, y_j, &proof)
            .unwrap_or(false));
        println!("✅ Test 3: Wrong evaluation point attack blocked");

        // Test 4: Attack with wrong coding vector should fail (binding property)
        let mut alpha_attack = alpha_coeffs.clone();
        alpha_attack[0] = alpha_attack[0] + Scalar::from(1u32);
        let wrong_commitment = msm_g1(&column_commitments, &alpha_attack).unwrap();
        assert_ne!(coded_commitment.as_ref(), wrong_commitment.as_ref());
        assert!(!committer
            .verify_proof(&wrong_commitment, x_j, y_j, &proof)
            .unwrap_or(false));
        println!("✅ Test 4: Wrong coding vector attack blocked (MSM binding)");

        // Multi-point (aggregated 1 proof) at points j and j+1 using kzg_rust multiproof
        let points: Vec<Scalar> = vec![
            derive_point(row_id, cell_idx),
            derive_point(row_id + 1, cell_idx),
        ];
        let (agg_proof, ys_multi) = committer
            .create_multi_point_proof(&coded_polynomial, &points)
            .unwrap();
        let packet_multi = CodedPiecePacketMulti {
            coefficients: hash[..n].to_vec(),
            ys: ys_multi.clone(),
            proofs: vec![agg_proof.clone()],
        };
        let piece_multi = CodedPiece {
            coefficients: packet_multi.coefficients.clone(),
            data: packet_multi.ys.clone(),
        };
        let ad_multi = KzgAdditional::Multi {
            points: points.clone(),
            proof: agg_proof,
            alpha_seed,
        };
        assert!(committer.verify(Some(&column_commitments), &piece_multi, Some(&ad_multi)));

        // === RESULTS ===
        println!("\n🎯 RLNC + KZG Implementation Results:");
        println!("• Formula: F*(X) = Σ α_i f_i(X)");
        println!("• Commitment: C* = Σ α_i C_i (MSM)");
        println!("• Single + Multi-point verifications passed");
    }

    #[test]
    fn rlnc_p2p_kzg_benchmark() {
        // Parameters
        const ROWS: usize = 64;
        const COLS: usize = 64;
        const CELL_SIZE: usize = 512; // bytes per cell (2MB / 4096)
        const CHUNKS_PER_CELL: usize = 8; // RLNC chunks per cell
        const BYTES_PER_CHUNK: usize = 64; // 64 bytes per chunk
        assert_eq!(CHUNKS_PER_CELL * BYTES_PER_CHUNK, CELL_SIZE);

        println!("=== RLNC + P2P + KZG Benchmark ===");
        println!(
            "Block: 2MB ({}x{} cells, {} bytes/cell)",
            ROWS, COLS, CELL_SIZE
        );

        // 1) Build synthetic 2MB block (deterministic pattern)
        let total_bytes = ROWS * COLS * CELL_SIZE;
        let mut block = vec![0u8; total_bytes];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut block);

        // 2) Build 64*8 polynomials: for each column and each chunk position (8 per cell)
        // Each chunk is 64 bytes -> 2 field elements per row => 128 scalars per (col,chunk)
        let mut polynomials_by_chunk: Vec<Vec<Vec<Scalar>>> =
            vec![Vec::with_capacity(COLS); CHUNKS_PER_CELL];
        for col in 0..COLS {
            for chunk_idx in 0..CHUNKS_PER_CELL {
                let mut scalars: Vec<Scalar> = Vec::with_capacity(ROWS * 2);
                for row in 0..ROWS {
                    let cell_idx = row * COLS + col;
                    let base = cell_idx * CELL_SIZE + chunk_idx * BYTES_PER_CHUNK;
                    let fe1 = Scalar::from_bytes(&block[base..base + 32]).expect("fe1");
                    let fe2 = Scalar::from_bytes(&block[base + 32..base + 64]).expect("fe2");
                    scalars.push(fe1);
                    scalars.push(fe2);
                }
                polynomials_by_chunk[chunk_idx].push(scalars);
            }
        }
        println!("Log: {:?}", polynomials_by_chunk.len());

        // 3) KZG: commit 64*8 polynomials and measure time
        let committer = KzgCommitter::new_insecure().unwrap();
        let t0 = std::time::Instant::now();
        let commitments_by_chunk: Vec<Vec<KzgCommitment>> = (0..CHUNKS_PER_CELL)
            .into_par_iter()
            .map(|chunk_idx| {
                polynomials_by_chunk[chunk_idx]
                    .par_iter()
                    .map(|poly| committer.commit_polynomial(poly).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect();
        let dt_commit = t0.elapsed();
        println!(
            "✓ Created {} column commitments ({} cols x {} chunks) in {:?}",
            COLS * CHUNKS_PER_CELL,
            COLS,
            CHUNKS_PER_CELL,
            dt_commit
        );

        // 4) RLNC coded cell at (row=0, col=0): derive α from seed
        let row_id: u8 = 0;
        let col_id: u8 = 0;
        let mut hasher = Sha256::new();
        hasher.update(b"rlnc-kzg-alpha-v1");
        hasher.update(&[row_id, col_id]);
        let seed = hasher.finalize();
        let mut alpha_seed = [0u8; 32];
        alpha_seed.copy_from_slice(&seed);
        let coefficents = expand_to_field(&alpha_seed, COLS);
        let alphas: Vec<Scalar> = coefficients_to_scalars(&coefficents);

        // 5) Build coded polynomial F*(X) = Σ α_i f_i(X)
        // 5) Build coded polynomial for a single chunk index (e.g., chunk 0)
        let chunk_idx = 0;
        let l = polynomials_by_chunk[chunk_idx][0].len();
        let mut coded_polynomial = vec![Scalar::from(0u32); l];
        for (f_i, a_i) in polynomials_by_chunk[chunk_idx].iter().zip(alphas.iter()) {
            for j in 0..l {
                coded_polynomial[j] = coded_polynomial[j] + (*a_i * f_i[j]);
            }
        }

        // 5b) Compute coded piece (row=0) for the chosen chunk index directly as Scalars
        let mut row0_fe0 = Scalar::from(0u32);
        let mut row0_fe1 = Scalar::from(0u32);
        for (col, a) in alphas.iter().enumerate() {
            let fe1 = polynomials_by_chunk[chunk_idx][col][0];
            let fe2 = polynomials_by_chunk[chunk_idx][col][1];
            row0_fe0 = row0_fe0 + (*a * fe1);
            row0_fe1 = row0_fe1 + (*a * fe2);
        }

        // 6) Compute coded commitment C* via MSM
        let t1 = std::time::Instant::now();
        let coded_commitment = msm_g1(&commitments_by_chunk[chunk_idx], &alphas).unwrap();
        let dt_msm = t1.elapsed();
        println!("✓ Computed coded commitment C* via MSM in {:?}", dt_msm);
        let computed_coded_commitment = committer.commit_polynomial(&coded_polynomial).unwrap();
        assert_eq!(
            coded_commitment.as_ref(),
            computed_coded_commitment.as_ref(),
            "C* from MSM must match C* from direct commit"
        );
        println!("✓ Verified C* from MSM matches direct commitment");

        // 7) Choose evaluation points for batch proof at roots of unity (domain points)
        // For row=0 we use indices j=0 and j=1 (two field elements per 64-byte chunk)
        let settings_roots: KzgSettings = Kzg::load_trusted_setup(
            committer.params.g1_points.clone(),
            committer.params.g2_points.clone(),
        )
        .expect("kzg settings for roots");
        let roots_of_unity = &settings_roots.roots_of_unity();
        let z0 = Scalar::from_blst_fr(&roots_of_unity[0]);
        let z1 = Scalar::from_blst_fr(&roots_of_unity[1]);
        let points = vec![z0, z1];

        // 8) Create multiproof for coded_polynomial at {z0, z1}
        let t2 = std::time::Instant::now();
        let (proof, ys) = committer
            .create_multi_point_proof(&coded_polynomial, &points)
            .expect("multi-point proof");
        let dt_prove = t2.elapsed();
        println!(
            "✓ Created multiproof for coded cell ({} points) in {:?}",
            points.len(),
            dt_prove
        );

        // Check that ys equals the coded piece at row=0 (two FEs) directly
        assert_eq!(ys[0], row0_fe0, "y0 must match coded piece FE0");
        assert_eq!(ys[1], row0_fe1, "y1 must match coded piece FE1");

        // 9) Verify the coded cell with multiproof (binding α)
        // Send any placeholder coefficients; verifier derives α from alpha_seed
        let piece_multi = CodedPiece {
            coefficients: coefficents.clone(),
            data: ys.clone(),
        };
        let ad_multi = KzgAdditional::Multi {
            points: points.clone(),
            proof: proof.clone(),
            alpha_seed,
        };
        let t3 = std::time::Instant::now();
        let ok = committer.verify(
            Some(&commitments_by_chunk[chunk_idx]),
            &piece_multi,
            Some(&ad_multi),
        );
        let dt_verify = t3.elapsed();
        assert!(ok, "Multiproof verification failed for coded cell");
        println!(
            "✓ Verified coded cell (row=0,col=0) with multiproof in {:?}",
            dt_verify
        );

        // Summary
        println!("\n=== Benchmark Summary ===");
        println!(
            "- Commit {} polynomials ({} cols x {} chunks): {:?}",
            COLS * CHUNKS_PER_CELL,
            COLS,
            CHUNKS_PER_CELL,
            dt_commit
        );
        println!("- MSM coded commitment: {:?}", dt_msm);
        println!("- Verify multiproof: {:?}", dt_verify);
    }

    #[test]
    fn test_basic_kzg_eval_first4() {
        let evals = vec![
            Scalar::from(1u32),
            Scalar::from(5u32),
            Scalar::from(7u32),
            Scalar::from(9u32),
        ];

        let committer = KzgCommitter::new_insecure().unwrap();
        let commitment = committer.commit_polynomial(&evals).unwrap();

        let settings: KzgSettings = Kzg::load_trusted_setup(
            committer.params.g1_points.clone(),
            committer.params.g2_points.clone(),
        )
        .expect("kzg settings");
        let blob = super::scalars_to_blob(&evals).expect("blob from evals");
        let roots_of_unity = &settings.roots_of_unity();

        for j in 0..4 {
            let fr_root = &roots_of_unity[j];
            let z = Scalar::from_blst_fr(fr_root);
            let z_bytes = super::bytes32_from_scalar_be(&z).expect("z bytes");

            let (proof, y_bytes) =
                Kzg::compute_kzg_proof(&blob, &z_bytes, &settings).expect("compute proof at ω^j");
            let y = Scalar::from_bytes(&*y_bytes).expect("y parse");
            assert_eq!(y, evals[j], "F(ω^{}) must equal evals[{}]", j, j);

            let ok = Kzg::verify_kzg_proof(&commitment, &z_bytes, &y_bytes, &proof, &settings)
                .expect("verify ω^j");
            assert!(ok, "single-point proof at z=ω^{} must verify", j);
        }
        println!("✓ Basic: proved and verified F(ω^j) for j=0..3 via single-point openings");
    }
}
