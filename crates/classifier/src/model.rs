use crate::tokens::{Document, TOKENIZER_VERSION, tokens};

/// Smallest table: 2^16 entries.
pub const MIN_BITS: u8 = 16;
/// Largest table: 2^24 entries.
pub const MAX_BITS: u8 = 24;

const MAGIC: &[u8; 8] = b"PELLETM1";
const HEADER_LEN: usize = 8 + 4 + 1 + 8 + 4 * 4 + 8 * 2;

/// How the table is sized and how FTRL learns.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Params {
    /// The table has 2^bits entries, between [`MIN_BITS`] and [`MAX_BITS`].
    pub bits: u8,
    /// Mixed into every hash; another seed gives another model.
    pub seed: u64,
    /// FTRL learning rate.
    pub alpha: f32,
    /// FTRL smoothing.
    pub beta: f32,
    /// L1 regularization: keeps rare tokens at zero.
    pub l1: f32,
    /// L2 regularization.
    pub l2: f32,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            bits: 18,
            seed: 0x5045_4c4c_4554,
            alpha: 0.2,
            beta: 1.0,
            l1: 0.1,
            l2: 1.0,
        }
    }
}

/// A model could not be built or read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    /// `bits` is outside [`MIN_BITS`]..=[`MAX_BITS`], or a parameter is not finite and positive.
    #[error("invalid model parameters: {0}")]
    Params(String),
    /// The bytes are not a model, are truncated, or have the wrong length.
    #[error("not a model file")]
    Format,
    /// The model was made by another tokenizer version, so its weights mean other tokens.
    #[error("model made by tokenizer version {0}, this is version {TOKENIZER_VERSION}")]
    Tokenizer(u32),
}

/// FTRL-proximal logistic regression over hashed tokens.
///
/// Each table entry holds the two FTRL accumulators as `f32`; the weight is derived from them,
/// so memory is 8 bytes per entry whatever the traffic. Training on one document touches only
/// its tokens.
#[derive(Debug, Clone, PartialEq)]
pub struct Model {
    params: Params,
    z: Vec<f32>,
    n: Vec<f32>,
    spam: u64,
    ham: u64,
}

fn fnv1a(seed: u64, token: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64 ^ seed;
    for &b in token.as_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x.clamp(-35.0, 35.0)).exp())
}

impl Model {
    /// An untrained model.
    pub fn new(params: Params) -> Result<Model, ModelError> {
        if !(MIN_BITS..=MAX_BITS).contains(&params.bits) {
            return Err(ModelError::Params(format!(
                "bits must be {MIN_BITS} to {MAX_BITS}, not {}",
                params.bits
            )));
        }
        for (name, value) in [("alpha", params.alpha), ("beta", params.beta)] {
            if !(value.is_finite() && value > 0.0) {
                return Err(ModelError::Params(format!("{name} must be positive")));
            }
        }
        for (name, value) in [("l1", params.l1), ("l2", params.l2)] {
            if !(value.is_finite() && value >= 0.0) {
                return Err(ModelError::Params(format!("{name} must not be negative")));
            }
        }
        let size = 1usize << params.bits;
        Ok(Model {
            params,
            z: vec![0.0; size],
            n: vec![0.0; size],
            spam: 0,
            ham: 0,
        })
    }

    /// Its parameters.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Samples trained so far, as (ham, spam).
    pub fn samples(&self) -> (u64, u64) {
        (self.ham, self.spam)
    }

    /// Bytes held by the table.
    pub fn memory_bytes(&self) -> usize {
        (self.z.len() + self.n.len()) * std::mem::size_of::<f32>()
    }

    fn features(&self, doc: &Document) -> Vec<usize> {
        let mask = (1u64 << self.params.bits) - 1;
        let mut indexes: Vec<usize> = tokens(doc)
            .iter()
            .map(|t| (fnv1a(self.params.seed, t) & mask) as usize)
            .collect();
        indexes.push(0);
        indexes.sort_unstable();
        indexes.dedup();
        indexes
    }

    fn weight(&self, i: usize) -> f64 {
        let p = &self.params;
        let z = f64::from(self.z[i]);
        let l1 = f64::from(p.l1);
        if z.abs() <= l1 {
            return 0.0;
        }
        let denominator = (f64::from(p.beta) + f64::from(self.n[i]).sqrt()) / f64::from(p.alpha)
            + f64::from(p.l2);
        -(z - z.signum() * l1) / denominator
    }

    fn margin(&self, features: &[usize]) -> f64 {
        features.iter().map(|&i| self.weight(i)).sum()
    }

    /// The probability that the document is spam, from 0 to 1; 0.5 for an untrained model.
    pub fn predict(&self, doc: &Document) -> f64 {
        sigmoid(self.margin(&self.features(doc)))
    }

    /// Learns one labeled document.
    pub fn train(&mut self, doc: &Document, spam: bool) {
        let features = self.features(doc);
        let p = sigmoid(self.margin(&features));
        let gradient = p - if spam { 1.0 } else { 0.0 };
        let alpha = f64::from(self.params.alpha);
        for &i in &features {
            let weight = self.weight(i);
            let n = f64::from(self.n[i]);
            let sigma = ((n + gradient * gradient).sqrt() - n.sqrt()) / alpha;
            self.z[i] = (f64::from(self.z[i]) + gradient - sigma * weight) as f32;
            self.n[i] = (n + gradient * gradient) as f32;
        }
        if spam {
            self.spam += 1;
        } else {
            self.ham += 1;
        }
    }

    /// The model as bytes: a header naming the format, the tokenizer version and every
    /// parameter, then the table, little endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.memory_bytes());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&TOKENIZER_VERSION.to_le_bytes());
        out.push(self.params.bits);
        out.extend_from_slice(&self.params.seed.to_le_bytes());
        for value in [
            self.params.alpha,
            self.params.beta,
            self.params.l1,
            self.params.l2,
        ] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&self.ham.to_le_bytes());
        out.extend_from_slice(&self.spam.to_le_bytes());
        for value in self.z.iter().chain(&self.n) {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }

    /// Reads a model written by [`Model::to_bytes`], refusing other tokenizer versions and
    /// bytes of the wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Model, ModelError> {
        if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
            return Err(ModelError::Format);
        }
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        let f32_at = |at: usize| f32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        let version = u32_at(8);
        if version != TOKENIZER_VERSION {
            return Err(ModelError::Tokenizer(version));
        }
        let params = Params {
            bits: bytes[12],
            seed: u64_at(13),
            alpha: f32_at(21),
            beta: f32_at(25),
            l1: f32_at(29),
            l2: f32_at(33),
        };
        let mut model = Model::new(params).map_err(|_| ModelError::Format)?;
        let size = model.z.len();
        if bytes.len() != HEADER_LEN + size * 8 {
            return Err(ModelError::Format);
        }
        model.ham = u64_at(37);
        model.spam = u64_at(45);
        for i in 0..size {
            model.z[i] = f32_at(HEADER_LEN + i * 4);
            model.n[i] = f32_at(HEADER_LEN + (size + i) * 4);
        }
        Ok(model)
    }
}

#[cfg(test)]
mod tests;
