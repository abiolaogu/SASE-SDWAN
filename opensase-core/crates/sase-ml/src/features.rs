//! Feature vector for ML models

/// Fixed-size feature vector for ML inference
#[derive(Debug, Clone)]
pub struct FeatureVector {
    data: Vec<f32>,
    dim: usize,
}

impl FeatureVector {
    /// Create new feature vector with dimension
    pub fn new(dim: usize) -> Self {
        Self {
            data: vec![0.0; dim],
            dim,
        }
    }

    /// Create from slice
    pub fn from_slice(data: &[f32]) -> Self {
        Self {
            dim: data.len(),
            data: data.to_vec(),
        }
    }

    /// Set feature at index
    #[inline]
    pub fn set(&mut self, index: usize, value: f32) {
        if index < self.dim {
            self.data[index] = value;
        }
    }

    /// Get feature at index
    #[inline]
    pub fn get(&self, index: usize) -> f32 {
        self.data.get(index).copied().unwrap_or(0.0)
    }

    /// Get dimension
    pub fn dim(&self) -> usize {
        self.dim
    }

    /// Get as slice
    pub fn as_slice(&self) -> &[f32] {
        &self.data
    }

    /// Normalize to [0, 1] range
    pub fn normalize(&mut self) {
        let min = self.data.iter().copied().fold(f32::MAX, f32::min);
        let max = self.data.iter().copied().fold(f32::MIN, f32::max);
        let range = max - min;
        
        if range > 0.001 {
            for x in &mut self.data {
                *x = (*x - min) / range;
            }
        }
    }

    /// L2 normalize
    pub fn l2_normalize(&mut self) {
        let norm: f32 = self.data.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.001 {
            for x in &mut self.data {
                *x /= norm;
            }
        }
    }

    /// Dot product with another vector
    pub fn dot(&self, other: &FeatureVector) -> f32 {
        self.data.iter()
            .zip(other.data.iter())
            .map(|(a, b)| a * b)
            .sum()
    }

    /// Euclidean distance
    pub fn distance(&self, other: &FeatureVector) -> f32 {
        self.data.iter()
            .zip(other.data.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f32>()
            .sqrt()
    }

    /// Cosine similarity
    pub fn cosine_similarity(&self, other: &FeatureVector) -> f32 {
        let dot = self.dot(other);
        let norm_a: f32 = self.data.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = other.data.iter().map(|x| x * x).sum::<f32>().sqrt();
        
        if norm_a > 0.001 && norm_b > 0.001 {
            dot / (norm_a * norm_b)
        } else {
            0.0
        }
    }
}

impl Default for FeatureVector {
    fn default() -> Self {
        Self::new(16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_vector() {
        let mut fv = FeatureVector::new(4);
        fv.set(0, 1.0);
        fv.set(1, 2.0);
        fv.set(2, 3.0);
        fv.set(3, 4.0);

        assert_eq!(fv.get(0), 1.0);
        assert_eq!(fv.get(3), 4.0);
    }

    #[test]
    fn test_normalize() {
        let mut fv = FeatureVector::from_slice(&[0.0, 50.0, 100.0]);
        fv.normalize();

        assert!((fv.get(0) - 0.0).abs() < 0.01);
        assert!((fv.get(1) - 0.5).abs() < 0.01);
        assert!((fv.get(2) - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_cosine_similarity() {
        let a = FeatureVector::from_slice(&[1.0, 0.0, 0.0]);
        let b = FeatureVector::from_slice(&[1.0, 0.0, 0.0]);
        let c = FeatureVector::from_slice(&[0.0, 1.0, 0.0]);

        assert!((a.cosine_similarity(&b) - 1.0).abs() < 0.01);  // Same direction
        assert!((a.cosine_similarity(&c) - 0.0).abs() < 0.01);  // Orthogonal
    }
}
