//! Face Recognition-based User Verification Provider
//!
//! Uses webcam and face recognition for user verification.
//!
//! # Requirements
//!
//! - Webcam device (V4L2 on Linux)
//! - face_id crate for detection and recognition
//! - ONNX Runtime (downloaded automatically)
//!
//! # Enrollment
//!
//! During enrollment, multiple face embeddings are captured and averaged
//! to create a robust template. The template is stored securely.

use super::{UserVerificationProvider, VerificationContext, VerificationError, VerificationResult};

use log::{debug, info, warn};

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use image::DynamicImage;
use nokhwa::Camera;
use nokhwa::pixel_format::RgbFormat;
use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};

#[allow(dead_code)]
const DEFAULT_THRESHOLD: f32 = 0.6;
#[allow(dead_code)]
const ENROLLMENT_SAMPLES: usize = 5;

/// Face recognition provider using webcam
pub struct FaceIdProvider {
    camera_index: usize,
    threshold: f32,
    embeddings_path: PathBuf,
    enrolled: Arc<Mutex<Option<bool>>>,
    analyzer: Arc<Mutex<Option<face_id::analyzer::FaceAnalyzer>>>,
}

impl FaceIdProvider {
    /// Create a new face recognition provider
    pub fn new(camera_index: usize, threshold: f32, embeddings_path: Option<PathBuf>) -> Self {
        let embeddings_path = embeddings_path.unwrap_or_else(|| {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("passless")
                .join("face_embeddings")
        });

        Self {
            camera_index,
            threshold,
            embeddings_path,
            enrolled: Arc::new(Mutex::new(None)),
            analyzer: Arc::new(Mutex::new(None)),
        }
    }

    /// Get path to the stored embeddings file
    fn embeddings_file(&self) -> PathBuf {
        self.embeddings_path.join("face_template.bin")
    }

    /// Check if a camera is available
    fn check_camera_available(&self) -> bool {
        let index = CameraIndex::Index(self.camera_index as u32);
        let format =
            RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);

        Camera::new(index, format).is_ok()
    }

    /// Initialize the face analyzer (downloads models if needed)
    fn init_analyzer(&self) -> Result<(), VerificationError> {
        let mut analyzer_guard = self.analyzer.lock().unwrap();

        if analyzer_guard.is_some() {
            return Ok(());
        }

        debug!("Initializing face analyzer (downloading models if needed)...");

        let rt = tokio::runtime::Runtime::new().map_err(|e| {
            VerificationError::DeviceError(format!("Failed to create runtime: {}", e))
        })?;

        let analyzer = rt.block_on(async {
            face_id::analyzer::FaceAnalyzer::from_hf()
                .build()
                .await
                .map_err(|e| {
                    VerificationError::DeviceError(format!(
                        "Failed to initialize face analyzer: {}",
                        e
                    ))
                })
        })?;

        *analyzer_guard = Some(analyzer);
        info!("Face analyzer initialized successfully");
        Ok(())
    }

    /// Capture a single frame from the camera
    fn capture_frame(&self) -> Result<DynamicImage, VerificationError> {
        debug!("Capturing frame from camera {}", self.camera_index);

        let index = CameraIndex::Index(self.camera_index as u32);
        let format =
            RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);

        let mut camera = Camera::new(index, format)
            .map_err(|e| VerificationError::DeviceError(format!("Failed to open camera: {}", e)))?;

        camera.open_stream().map_err(|e| {
            VerificationError::DeviceError(format!("Failed to start camera stream: {}", e))
        })?;

        let buffer = camera.frame().map_err(|e| {
            VerificationError::DeviceError(format!("Failed to capture frame: {}", e))
        })?;

        let decoded = buffer.decode_image::<RgbFormat>().map_err(|e| {
            VerificationError::DeviceError(format!("Failed to decode frame: {}", e))
        })?;

        camera
            .stop_stream()
            .map_err(|e| warn!("Failed to stop camera stream: {}", e))
            .ok();

        Ok(DynamicImage::ImageRgb8(decoded))
    }

    /// Extract face embedding from an image
    fn extract_embedding(&self, image: &DynamicImage) -> Result<Vec<f32>, VerificationError> {
        self.init_analyzer()?;

        let analyzer_guard = self.analyzer.lock().unwrap();
        let analyzer = analyzer_guard.as_ref().unwrap();

        debug!("Analyzing image for face");

        let results = analyzer
            .analyze(image)
            .map_err(|e| VerificationError::DeviceError(format!("Face analysis failed: {}", e)))?;

        if results.is_empty() {
            return Err(VerificationError::DeviceError("No face detected".into()));
        }

        if results.len() > 1 {
            warn!("Multiple faces detected, using the first one");
        }

        let face = &results[0];
        debug!(
            "Extracted embedding with {} dimensions",
            face.embedding.len()
        );
        Ok(face.embedding.clone())
    }

    /// Load stored embeddings template
    fn load_template(&self) -> Result<Vec<f32>, VerificationError> {
        let path = self.embeddings_file();
        if !path.exists() {
            return Err(VerificationError::NotEnrolled);
        }

        let data = std::fs::read(&path).map_err(|e| {
            VerificationError::DeviceError(format!("Failed to read template: {}", e))
        })?;

        let embedding_len = u64::from_le_bytes(
            data.get(0..8)
                .ok_or_else(|| VerificationError::DeviceError("Invalid template format".into()))?
                .try_into()
                .unwrap(),
        ) as usize;

        let embedding: Vec<f32> = data[8..]
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();

        if embedding.len() != embedding_len {
            return Err(VerificationError::DeviceError(
                "Template length mismatch".into(),
            ));
        }

        Ok(embedding)
    }

    /// Save embeddings template
    #[allow(dead_code)]
    fn save_template(&self, embedding: &[f32]) -> Result<(), VerificationError> {
        std::fs::create_dir_all(&self.embeddings_path).map_err(|e| {
            VerificationError::DeviceError(format!("Failed to create embeddings directory: {}", e))
        })?;

        let path = self.embeddings_file();

        let mut data = Vec::with_capacity(8 + embedding.len() * 4);
        data.extend_from_slice(&(embedding.len() as u64).to_le_bytes());
        for &val in embedding {
            data.extend_from_slice(&val.to_le_bytes());
        }

        std::fs::write(&path, &data).map_err(|e| {
            VerificationError::DeviceError(format!("Failed to write template: {}", e))
        })?;

        info!("Saved face template to {}", path.display());
        Ok(())
    }

    /// Calculate cosine similarity between two embeddings
    fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() {
            return 0.0;
        }

        let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let mag_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let mag_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

        if mag_a == 0.0 || mag_b == 0.0 {
            return 0.0;
        }

        dot_product / (mag_a * mag_b)
    }

    /// Perform face verification
    fn do_verification(&self) -> Result<VerificationResult, VerificationError> {
        let template = self.load_template()?;

        let frame = self.capture_frame()?;
        let embedding = self.extract_embedding(&frame)?;

        let similarity = Self::cosine_similarity(&template, &embedding);
        debug!("Face similarity score: {}", similarity);

        if similarity >= self.threshold {
            info!("Face matched (similarity: {})", similarity);
            Ok(VerificationResult::Accepted)
        } else {
            info!(
                "Face not matched (similarity: {} < {})",
                similarity, self.threshold
            );
            Ok(VerificationResult::Denied)
        }
    }
}

impl UserVerificationProvider for FaceIdProvider {
    fn name(&self) -> &str {
        "face"
    }

    fn available(&self) -> bool {
        self.check_camera_available()
    }

    fn verify(
        &self,
        _context: &VerificationContext,
    ) -> Result<VerificationResult, VerificationError> {
        self.do_verification()
    }

    fn priority(&self) -> u8 {
        90
    }

    fn supports_enrollment(&self) -> bool {
        true
    }

    fn requires_enrollment(&self) -> bool {
        true
    }

    fn is_enrolled(&self) -> bool {
        if let Some(enrolled) = *self.enrolled.lock().unwrap() {
            return enrolled;
        }

        let enrolled = self.embeddings_file().exists();
        *self.enrolled.lock().unwrap() = Some(enrolled);
        enrolled
    }

    fn enroll(&self) -> Result<(), VerificationError> {
        info!(
            "Starting face enrollment (capturing {} samples)",
            ENROLLMENT_SAMPLES
        );

        self.init_analyzer()?;

        let mut embeddings: Vec<Vec<f32>> = Vec::with_capacity(ENROLLMENT_SAMPLES);

        for i in 0..ENROLLMENT_SAMPLES {
            debug!(
                "Capturing enrollment sample {}/{}",
                i + 1,
                ENROLLMENT_SAMPLES
            );

            let frame = self.capture_frame()?;
            let embedding = self.extract_embedding(&frame)?;
            embeddings.push(embedding);

            if i < ENROLLMENT_SAMPLES - 1 {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }

        let avg_embedding: Vec<f32> = {
            let len = embeddings[0].len();
            let mut sum = vec![0.0f32; len];

            for embedding in &embeddings {
                for (i, &val) in embedding.iter().enumerate() {
                    sum[i] += val;
                }
            }

            let n = embeddings.len() as f32;
            sum.into_iter().map(|x| x / n).collect()
        };

        self.save_template(&avg_embedding)?;

        *self.enrolled.lock().unwrap() = Some(true);

        info!("Face enrollment completed successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_face_provider_name() {
        let provider = FaceIdProvider::new(0, DEFAULT_THRESHOLD, None);
        assert_eq!(provider.name(), "face");
    }

    #[test]
    fn test_face_provider_priority() {
        let provider = FaceIdProvider::new(0, DEFAULT_THRESHOLD, None);
        assert_eq!(provider.priority(), 90);
    }

    #[test]
    fn test_face_provider_supports_enrollment() {
        let provider = FaceIdProvider::new(0, DEFAULT_THRESHOLD, None);
        assert!(provider.supports_enrollment());
    }

    #[test]
    fn test_face_provider_requires_enrollment() {
        let provider = FaceIdProvider::new(0, DEFAULT_THRESHOLD, None);
        assert!(provider.requires_enrollment());
    }

    #[test]
    fn test_face_provider_not_enrolled_initially() {
        let temp_dir = tempfile::tempdir().unwrap();
        let provider = FaceIdProvider::new(
            0,
            DEFAULT_THRESHOLD,
            Some(temp_dir.path().join("face_embeddings")),
        );
        assert!(!provider.is_enrolled());
    }

    #[test]
    fn test_cosine_similarity_identical() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        let sim = FaceIdProvider::cosine_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        let sim = FaceIdProvider::cosine_similarity(&a, &b);
        assert!(sim.abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity_opposite() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![-1.0, 0.0, 0.0];
        let sim = FaceIdProvider::cosine_similarity(&a, &b);
        assert!((sim - (-1.0)).abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity_partial() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 1.0, 0.0];
        let sim = FaceIdProvider::cosine_similarity(&a, &b);
        let expected = std::f32::consts::FRAC_1_SQRT_2;
        assert!((sim - expected).abs() < 0.01);
    }

    #[test]
    fn test_cosine_similarity_different_lengths() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0];
        let sim = FaceIdProvider::cosine_similarity(&a, &b);
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn test_cosine_similarity_zero_vectors() {
        let a = vec![0.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        let sim = FaceIdProvider::cosine_similarity(&a, &b);
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn test_cosine_similarity_high_dim() {
        let a: Vec<f32> = (0..512)
            .map(|i| if i % 2 == 0 { 1.0 } else { 0.0 })
            .collect();
        let b: Vec<f32> = (0..512)
            .map(|i| if i % 2 == 0 { 1.0 } else { 0.5 })
            .collect();
        let sim = FaceIdProvider::cosine_similarity(&a, &b);
        assert!(sim > 0.8 && sim < 1.0);
    }
}
