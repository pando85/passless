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

use super::{
    UserVerificationProvider, VerificationContext, VerificationError, VerificationResult, priority,
};

use log::{debug, info, warn};

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

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
            analyzer: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a provider if enabled in config
    pub fn from_config(
        enabled: bool,
        camera_index: usize,
        threshold: f32,
    ) -> Option<Box<dyn UserVerificationProvider>> {
        if enabled {
            Some(Box::new(Self::new(camera_index, threshold, None)))
        } else {
            None
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
            return Err(VerificationError::DeviceError(
                "Multiple faces detected; only one person may be in frame".into(),
            ));
        }

        let face = &results[0];
        debug!(
            "Extracted embedding with {} dimensions",
            face.embedding.len()
        );
        Ok(face.embedding.clone())
    }

    /// Load an enrolled template from a private, regular file.
    fn load_template(&self) -> Result<Vec<f32>, VerificationError> {
        let path = self.embeddings_file();
        let meta = std::fs::symlink_metadata(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VerificationError::NotEnrolled
            } else {
                VerificationError::DeviceError(format!("Failed to inspect template: {}", e))
            }
        })?;
        if !meta.file_type().is_file() {
            return Err(VerificationError::DeviceError(
                "Face template must be a regular file".into(),
            ));
        }
        #[cfg(unix)]
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(VerificationError::DeviceError(
                "Face template permissions must be 0600".into(),
            ));
        }
        let data = std::fs::read(&path).map_err(|e| {
            VerificationError::DeviceError(format!("Failed to read template: {}", e))
        })?;
        if data.len() < 8 {
            return Err(VerificationError::DeviceError("Truncated face template".into()));
        }
        let length = u64::from_le_bytes(data[0..8].try_into().unwrap());
        if length == 0 || length > 4096 || data.len() as u64 != 8 + length * 4 {
            return Err(VerificationError::DeviceError("Invalid face template length".into()));
        }
        let embedding: Vec<f32> = data[8..]
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        if !embedding.iter().all(|value| value.is_finite()) {
            return Err(VerificationError::DeviceError("Invalid face template value".into()));
        }
        Ok(embedding)
    }

    /// Atomically save a template with owner-only access; never follow output symlinks.
    fn save_template(&self, embedding: &[f32]) -> Result<(), VerificationError> {
        if embedding.is_empty() || embedding.len() > 4096
            || !embedding.iter().all(|value| value.is_finite())
        {
            return Err(VerificationError::DeviceError("Invalid face embedding".into()));
        }
        #[cfg(unix)]
        {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(&self.embeddings_path).map_err(|e| {
                VerificationError::DeviceError(format!("Failed to create template directory: {}", e))
            })?;
            std::fs::set_permissions(
                &self.embeddings_path,
                std::fs::Permissions::from_mode(0o700),
            )?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(&self.embeddings_path)?;

        let path = self.embeddings_file();
        let tmp_path = self.embeddings_path.join(format!(
            ".face_template-{}.tmp", std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp_path).map_err(|e| {
            VerificationError::DeviceError(format!("Failed to create temporary template: {}", e))
        })?;
        let mut data = Vec::with_capacity(8 + embedding.len() * 4);
        data.extend_from_slice(&(embedding.len() as u64).to_le_bytes());
        for &value in embedding {
            data.extend_from_slice(&value.to_le_bytes());
        }
        if let Err(e) = file.write_all(&data).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(VerificationError::DeviceError(format!("Failed to save template: {}", e)));
        }
        drop(file);
        if let Err(e) = std::fs::rename(&tmp_path, &path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(VerificationError::DeviceError(format!("Failed to install template: {}", e)));
        }
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
        priority::FACE
    }

    fn supports_enrollment(&self) -> bool {
        true
    }

    fn requires_enrollment(&self) -> bool {
        true
    }

    fn is_enrolled(&self) -> bool {
        self.embeddings_file().is_file()
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
        assert_eq!(provider.priority(), priority::FACE);
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
    fn test_reject_malformed_template() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = FaceIdProvider::new(0, DEFAULT_THRESHOLD, Some(tmp.path().into()));
        std::fs::write(provider.embeddings_file(), [0u8, 1, 2]).unwrap();
        assert!(provider.load_template().is_err());
    }

    #[test]
    fn test_face_template_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = FaceIdProvider::new(0, DEFAULT_THRESHOLD, Some(tmp.path().join("face")));
        let template = vec![0.1, -0.2, 0.3, 0.4];
        provider.save_template(&template).unwrap();
        assert_eq!(provider.load_template().unwrap(), template);
        assert!(provider.is_enrolled());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::metadata(provider.embeddings_file()).unwrap().permissions();
            assert_eq!(permissions.mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_reject_invalid_embedding_values() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = FaceIdProvider::new(0, DEFAULT_THRESHOLD, Some(tmp.path().join("face")));
        assert!(provider.save_template(&[f32::NAN]).is_err());
        assert!(provider.save_template(&[]).is_err());
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
