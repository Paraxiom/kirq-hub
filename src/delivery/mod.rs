use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod push_client;
pub mod quantum_harmony_push;

use crate::sources::SourceManager;
use crate::mixing::{EntropyMixer, MixingProof};

#[derive(Deserialize)]
pub struct EntropyRequest {
    pub num_bytes: usize,
    #[serde(default = "default_sources")]
    pub sources: Vec<String>,
    #[serde(default)]
    pub proof_required: bool,
}

fn default_sources() -> Vec<String> {
    vec!["crypto4a".to_string()]
}

#[derive(Serialize)]
pub struct EntropyResponse {
    pub entropy: String,
    pub encoding: String,
    pub sources_used: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<MixingProof>,
}

#[derive(Deserialize)]
pub struct SourceEntropyRequest {
    pub num_bytes: usize,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub sources: Vec<SourceHealth>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct SourceHealth {
    pub name: String,
    pub healthy: bool,
}

pub async fn health(
    source_manager: web::Data<Arc<SourceManager>>
) -> HttpResponse {
    let health_status = source_manager.get_health_status().await;
    
    let sources: Vec<SourceHealth> = health_status
        .into_iter()
        .map(|(name, healthy)| SourceHealth { name, healthy })
        .collect();

    let all_healthy = sources.iter().all(|s| s.healthy);
    
    HttpResponse::Ok().json(HealthResponse {
        status: if all_healthy { "healthy".to_string() } else { "degraded".to_string() },
        sources,
        timestamp: chrono::Utc::now(),
    })
}

pub async fn get_mixed_entropy(
    req: web::Json<EntropyRequest>,
    source_manager: web::Data<Arc<SourceManager>>
) -> HttpResponse {
    // Validate request
    if req.num_bytes == 0 || req.num_bytes > 1024 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "num_bytes must be between 1 and 1024"
        }));
    }

    // Get entropy from sources
    match source_manager.get_mixed_entropy(req.num_bytes, req.sources.clone()).await {
        Ok(entropy) => {
            let mut response = EntropyResponse {
                entropy: hex::encode(&entropy),
                encoding: "hex".to_string(),
                sources_used: req.sources.clone(),
                timestamp: chrono::Utc::now(),
                proof: None,
            };

            // Generate proof if requested
            if req.proof_required {
                // For now, skip proof generation in mixed mode
                // This would require passing the individual parts through
            }

            HttpResponse::Ok().json(response)
        }
        Err(e) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": format!("Failed to get entropy: {}", e)
        }))
    }
}

pub async fn get_source_entropy(
    path: web::Path<String>,
    req: web::Json<SourceEntropyRequest>,
    source_manager: web::Data<Arc<SourceManager>>
) -> HttpResponse {
    let source_name = path.into_inner();

    // Validate request
    if req.num_bytes == 0 || req.num_bytes > 1024 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "num_bytes must be between 1 and 1024"
        }));
    }

    // Get entropy from specific source
    match source_manager.get_entropy_from_source(&source_name, req.num_bytes).await {
        Ok(entropy) => {
            HttpResponse::Ok().json(EntropyResponse {
                entropy: hex::encode(&entropy),
                encoding: "hex".to_string(),
                sources_used: vec![source_name],
                timestamp: chrono::Utc::now(),
                proof: None,
            })
        }
        Err(e) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": format!("Failed to get entropy from {}: {}", source_name, e)
        }))
    }
}

pub async fn list_sources(
    source_manager: web::Data<Arc<SourceManager>>
) -> HttpResponse {
    let health_status = source_manager.get_health_status().await;
    
    HttpResponse::Ok().json(serde_json::json!({
        "sources": health_status
    }))
}