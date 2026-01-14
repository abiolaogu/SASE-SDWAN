//! Pixel Encoder
//!
//! H.264/VP9/AV1 video encoding for pixel-push streaming.

use crate::{VideoCodec, StreamQuality, StreamConfig, Viewport};

/// Pixel encoder for video streaming
pub struct PixelEncoder {
    config: EncoderConfig,
    frame_count: u64,
    last_keyframe: u64,
    stats: EncoderStats,
}

#[derive(Debug, Clone)]
pub struct EncoderConfig {
    pub codec: VideoCodec,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
    pub keyframe_interval: u32,
    pub quality: StreamQuality,
    /// Hardware acceleration
    pub hardware_accel: bool,
    /// B-frames (latency vs compression)
    pub b_frames: u32,
    /// Constant rate factor (quality vs bitrate)
    pub crf: u32,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            codec: VideoCodec::H264,
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_kbps: 5000,
            keyframe_interval: 60,
            quality: StreamQuality::High,
            hardware_accel: true,
            b_frames: 0, // No B-frames for low latency
            crf: 23,
        }
    }
}

impl EncoderConfig {
    pub fn from_stream_config(stream: &StreamConfig, viewport: Viewport) -> Self {
        Self {
            codec: stream.codec,
            width: viewport.width,
            height: viewport.height,
            fps: stream.max_fps,
            bitrate_kbps: stream.max_bitrate_kbps,
            keyframe_interval: stream.keyframe_interval,
            quality: stream.quality,
            ..Default::default()
        }
    }
    
    /// Generate FFmpeg arguments
    pub fn ffmpeg_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        
        match self.codec {
            VideoCodec::H264 => {
                if self.hardware_accel {
                    args.extend_from_slice(&[
                        "-c:v".to_string(), "h264_nvenc".to_string(),
                    ]);
                } else {
                    args.extend_from_slice(&[
                        "-c:v".to_string(), "libx264".to_string(),
                    ]);
                }
                
                args.extend_from_slice(&[
                    "-preset".to_string(), "ultrafast".to_string(),
                    "-tune".to_string(), "zerolatency".to_string(),
                    "-profile:v".to_string(), "baseline".to_string(),
                    "-level".to_string(), "4.1".to_string(),
                    format!("-crf:v {}", self.crf),
                ]);
            }
            VideoCodec::VP9 => {
                args.extend_from_slice(&[
                    "-c:v".to_string(), "libvpx-vp9".to_string(),
                    "-deadline".to_string(), "realtime".to_string(),
                    "-cpu-used".to_string(), "8".to_string(),
                ]);
            }
            VideoCodec::AV1 => {
                args.extend_from_slice(&[
                    "-c:v".to_string(), "libaom-av1".to_string(),
                    "-cpu-used".to_string(), "8".to_string(),
                    "-usage".to_string(), "realtime".to_string(),
                ]);
            }
        }
        
        args.extend_from_slice(&[
            "-b:v".to_string(), format!("{}k", self.bitrate_kbps),
            "-maxrate".to_string(), format!("{}k", self.bitrate_kbps * 2),
            "-bufsize".to_string(), format!("{}k", self.bitrate_kbps),
            "-r".to_string(), format!("{}", self.fps),
            "-g".to_string(), format!("{}", self.keyframe_interval),
            "-bf".to_string(), format!("{}", self.b_frames),
        ]);
        
        args
    }
}

#[derive(Debug, Clone)]
pub struct EncodedFrame {
    pub timestamp_ms: u64,
    pub keyframe: bool,
    pub data: Vec<u8>,
    pub size: usize,
}

#[derive(Debug, Default)]
struct EncoderStats {
    frames_encoded: std::sync::atomic::AtomicU64,
    keyframes_encoded: std::sync::atomic::AtomicU64,
    bytes_encoded: std::sync::atomic::AtomicU64,
    encode_time_us: std::sync::atomic::AtomicU64,
}

impl PixelEncoder {
    pub fn new(config: EncoderConfig) -> Self {
        Self {
            config,
            frame_count: 0,
            last_keyframe: 0,
            stats: EncoderStats::default(),
        }
    }
    
    /// Encode raw frame to video
    pub fn encode(&mut self, raw_rgba: &[u8]) -> Result<EncodedFrame, String> {
        use std::sync::atomic::Ordering;
        
        let start = std::time::Instant::now();
        
        self.frame_count += 1;
        let keyframe = self.frame_count - self.last_keyframe >= self.config.keyframe_interval as u64;
        
        if keyframe {
            self.last_keyframe = self.frame_count;
        }
        
        // In production, this would call actual encoder (FFmpeg, NVENC, etc.)
        let encoded = self.mock_encode(raw_rgba, keyframe);
        
        let elapsed = start.elapsed().as_micros() as u64;
        
        self.stats.frames_encoded.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_encoded.fetch_add(encoded.len() as u64, Ordering::Relaxed);
        self.stats.encode_time_us.fetch_add(elapsed, Ordering::Relaxed);
        
        if keyframe {
            self.stats.keyframes_encoded.fetch_add(1, Ordering::Relaxed);
        }
        
        Ok(EncodedFrame {
            timestamp_ms: self.frame_count * 1000 / self.config.fps as u64,
            keyframe,
            size: encoded.len(),
            data: encoded,
        })
    }
    
    /// Force keyframe on next encode
    pub fn force_keyframe(&mut self) {
        self.last_keyframe = 0;
    }
    
    /// Get encoder statistics
    pub fn get_stats(&self) -> EncoderSnapshot {
        use std::sync::atomic::Ordering;
        
        let frames = self.stats.frames_encoded.load(Ordering::Relaxed);
        let time_us = self.stats.encode_time_us.load(Ordering::Relaxed);
        
        EncoderSnapshot {
            frames_encoded: frames,
            keyframes_encoded: self.stats.keyframes_encoded.load(Ordering::Relaxed),
            bytes_encoded: self.stats.bytes_encoded.load(Ordering::Relaxed),
            avg_encode_time_us: if frames > 0 { time_us / frames } else { 0 },
        }
    }
    
    fn mock_encode(&self, _raw: &[u8], keyframe: bool) -> Vec<u8> {
        // Placeholder - real implementation would use actual encoder
        if keyframe {
            // NAL unit start code + SPS/PPS for keyframe
            vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xc0, 0x1e]
        } else {
            // NAL unit start code + P-frame slice
            vec![0x00, 0x00, 0x01, 0x41, 0x9a, 0x00]
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncoderSnapshot {
    pub frames_encoded: u64,
    pub keyframes_encoded: u64,
    pub bytes_encoded: u64,
    pub avg_encode_time_us: u64,
}

/// WebRTC frame packetizer
pub struct RtpPacketizer {
    ssrc: u32,
    sequence: u16,
    timestamp: u32,
    mtu: usize,
}

impl RtpPacketizer {
    pub fn new(ssrc: u32) -> Self {
        Self {
            ssrc,
            sequence: 0,
            timestamp: 0,
            mtu: 1200,
        }
    }
    
    /// Packetize encoded frame into RTP packets
    pub fn packetize(&mut self, frame: &EncodedFrame) -> Vec<RtpPacket> {
        let mut packets = Vec::new();
        let chunks: Vec<_> = frame.data.chunks(self.mtu - 12).collect();
        
        for (i, chunk) in chunks.iter().enumerate() {
            let marker = i == chunks.len() - 1;
            
            let packet = RtpPacket {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker,
                payload_type: 96, // Dynamic H.264
                sequence: self.sequence,
                timestamp: self.timestamp,
                ssrc: self.ssrc,
                payload: chunk.to_vec(),
            };
            
            self.sequence = self.sequence.wrapping_add(1);
            packets.push(packet);
        }
        
        // Increment timestamp by frame duration
        self.timestamp = self.timestamp.wrapping_add(3000); // 90000 / 30fps
        
        packets
    }
}

#[derive(Debug, Clone)]
pub struct RtpPacket {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload: Vec<u8>,
}

impl RtpPacket {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.payload.len());
        
        // First byte: V=2, P, X, CC
        let b0 = (self.version << 6) | 
                 ((self.padding as u8) << 5) |
                 ((self.extension as u8) << 4) |
                 self.csrc_count;
        buf.push(b0);
        
        // Second byte: M, PT
        let b1 = ((self.marker as u8) << 7) | self.payload_type;
        buf.push(b1);
        
        // Sequence number
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        
        // Timestamp
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        
        // SSRC
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        
        // Payload
        buf.extend_from_slice(&self.payload);
        
        buf
    }
}
