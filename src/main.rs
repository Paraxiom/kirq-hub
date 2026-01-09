use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use anyhow::Result;
use log::info;
use std::sync::Arc;

mod config;
mod delivery;
mod entropy_pool;
mod mixing;
mod quantum_rng;
mod quantum_state;
mod sources;

use config::Config;
use sources::SourceManager;

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    info!("Starting Quantum RNG Kirk Hub v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = Config::load("config.toml").unwrap_or_else(|_| {
        info!("config.toml not found, using defaults");
        Config {
            server: config::ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8001,
                workers: 4,
            },
            sources: config::Sources {
                qrng: config::QrngConfig {
                    enabled: false,
                    endpoint: String::new(),
                    api_key: String::new(),
                    timeout_ms: 5000,
                    weight: 1.0,
                },
                crypto4a: config::Crypto4aConfig {
                    enabled: true,
                    endpoint: "http://localhost:8106/v1/random".to_string(),
                    timeout_ms: 1000,
                    weight: 1.0,
                },
                decentralized: config::DecentralizedConfig {
                    enabled: false,
                    nodes: vec![],
                    min_nodes: 2,
                    timeout_ms: 3000,
                    weight: 1.0,
                },
                quantum_vault: Some(config::QuantumVaultConfig {
                    enabled: true,
                    weight: 2.0,
                    measurement_rounds: 3,
                }),
            },
            mixing: config::MixingConfig {
                algorithm: "hybrid_xor_hkdf".to_string(),
                salt: "kirk-hub-v1".to_string(),
                info: "quantum-entropy-mix".to_string(),
            },
            delivery: config::DeliveryConfig {
                max_entropy_age_seconds: 60,
                require_proof: true,
                enable_metrics: true,
                quantum_harmony_push: None,
            },
            security: config::SecurityConfig {
                enable_falcon_signatures: false,
                enable_stark_proofs: false,
                tls_cert: None,
                tls_key: None,
            },
            metrics: config::MetricsConfig {
                enabled: false,
                port: 9090,
            },
        }
    });

    let bind_addr = format!("{}:{}", config.server.host, config.server.port);

    // Initialize source manager
    let source_manager = Arc::new(SourceManager::new(config.clone()).await?);

    // Start health check background task
    let health_checker = source_manager.clone();
    tokio::spawn(async move {
        loop {
            health_checker.check_sources_health().await;
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    });

    // Start Quantum Harmony push client if configured
    let qh_config = config.delivery.quantum_harmony_push.clone();
    if let Some(qh_cfg) = qh_config {
        if qh_cfg.enabled {
            let qh_manager = source_manager.clone();
            tokio::spawn(async move {
                info!("Starting Quantum Harmony push client to {}", qh_cfg.rpc_endpoint);
                match delivery::quantum_harmony_push::QuantumHarmonyPushClient::new(
                    qh_cfg.rpc_endpoint.clone(),
                    qh_manager,
                ) {
                    Ok(client) => {
                        client.start_push_loop(qh_cfg.push_interval_secs, qh_cfg.entropy_bytes_per_push).await;
                    }
                    Err(e) => {
                        log::error!("Failed to create Quantum Harmony push client: {}", e);
                    }
                }
            });
        }
    } else if let Ok(qh_endpoint) = std::env::var("QUANTUM_HARMONY_RPC") {
        // Fallback to env var for backwards compatibility
        let qh_manager = source_manager.clone();
        tokio::spawn(async move {
            info!("Starting Quantum Harmony push client to {} (from env)", qh_endpoint);
            match delivery::quantum_harmony_push::QuantumHarmonyPushClient::new(
                qh_endpoint,
                qh_manager,
            ) {
                Ok(client) => {
                    let interval = std::env::var("PUSH_INTERVAL_SECS")
                        .unwrap_or_else(|_| "60".to_string())
                        .parse::<u64>()
                        .unwrap_or(60);
                    let bytes = std::env::var("ENTROPY_BYTES_PER_PUSH")
                        .unwrap_or_else(|_| "32".to_string())
                        .parse::<usize>()
                        .unwrap_or(32);
                    client.start_push_loop(interval, bytes).await;
                }
                Err(e) => {
                    log::error!("Failed to create Quantum Harmony push client: {}", e);
                }
            }
        });
    }

    info!("Kirk Hub listening on {}", bind_addr);

    // Start HTTP server
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .app_data(web::Data::new(source_manager.clone()))
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .service(
                web::scope("/api")
                    .route("/health", web::get().to(delivery::health))
                    .route("/entropy/mixed", web::post().to(delivery::get_mixed_entropy))
                    .route("/entropy/source/{name}", web::post().to(delivery::get_source_entropy))
                    .route("/sources", web::get().to(delivery::list_sources))
            )
    })
    .bind(&bind_addr)?
    .workers(config.server.workers)
    .run()
    .await?;

    Ok(())
}