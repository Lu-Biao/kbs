// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use async_trait::async_trait;
#[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
use attestation_service::config::Config as AsConfig;
#[cfg(feature = "coco-as-grpc")]
use coco::grpc::GrpcConfig;
#[cfg(feature = "intel-trust-authority-as")]
use intel_trust_authority::IntelTrustAuthorityConfig;
use kbs_types::Tee;

#[cfg(feature = "coco-as")]
#[allow(missing_docs)]
pub mod coco;

#[cfg(feature = "intel-trust-authority-as")]
pub mod intel_trust_authority;

/// Interface for Attestation Services.
///
/// Attestation Service implementations should implement this interface.
#[async_trait]
pub trait Attest: Send + Sync {
    /// Set Attestation Policy
    async fn set_policy(&mut self, _input: &[u8]) -> Result<()> {
        Err(anyhow!("Set Policy API is unimplemented"))
    }

    /// Verify Attestation Evidence
    /// Return Attestation Results Token
    async fn verify(
        &mut self,
        tee: Tee,
        nonce: &str,
        attestation: &str,
        request_id: &str,
    ) -> Result<String>;
}

/// Attestation Service
#[derive(Clone)]
pub enum AttestationService {
    #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
    CoCoASBuiltIn(AsConfig),

    #[cfg(feature = "coco-as-grpc")]
    CoCoASgRPC(GrpcConfig),

    #[cfg(feature = "intel-trust-authority-as")]
    IntelTA(IntelTrustAuthorityConfig),
}

impl AttestationService {
    /// Create and initialize AttestationService.
    #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
    pub fn new(config: AsConfig) -> Self {
        Self::CoCoASBuiltIn(config)
    }

    /// Create and initialize AttestationService.
    #[cfg(feature = "coco-as-grpc")]
    pub fn new(config: GrpcConfig) -> Self {
        Self::CoCoASgRPC(config)
    }

    /// Create and initialize AttestationService.
    #[cfg(feature = "intel-trust-authority-as")]
    pub fn new(config: IntelTrustAuthorityConfig) -> Self {
        Self::IntelTA(config)
    }

    pub async fn create_client(&self) -> Result<Box<dyn Attest>> {
        match self {
            #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
            AttestationService::CoCoASBuiltIn(config) => {
                Ok(Box::new(coco::builtin::Native::new(config).await?))
            }
            #[cfg(feature = "coco-as-grpc")]
            AttestationService::CoCoASgRPC(config) => {
                Ok(Box::new(coco::grpc::Grpc::new(config).await?))
            }
            #[cfg(feature = "intel-trust-authority-as")]
            AttestationService::IntelTA(config) => Ok(Box::new(
                intel_trust_authority::IntelTrustAuthority::new(config)?,
            )),
        }
    }

    pub async fn verify(
        &self,
        tee: Tee,
        nonce: &str,
        attestation: &str,
        request_id: &str,
    ) -> Result<String> {
        let mut client = self
            .create_client()
            .await
            .context("attestation service client initialization failed.")?;
        client.verify(tee, nonce, attestation, request_id).await
    }

    pub async fn set_policy(&self, input: &[u8]) -> Result<()> {
        let mut client = self
            .create_client()
            .await
            .context("attestation service client initialization failed.")?;
        client.set_policy(input).await
    }
}
