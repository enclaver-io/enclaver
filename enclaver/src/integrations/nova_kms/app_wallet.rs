use anyhow::{Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose};
use log::warn;
use zeroize::Zeroize;

use crate::eth_key::EthKey;

use super::{
    APP_WALLET_CACHE_TTL_MS, APP_WALLET_KV_ADDRESS, APP_WALLET_KV_PRIVATE_KEY, AppAuthzContext,
    AppWalletMaterial, CachedAppWallet, NovaKmsProxy, canonical_wallet, current_unix_millis,
    decode_kms_private_key_hex, decode_kms_wallet_address, trim_0x,
};

impl NovaKmsProxy {
    pub async fn ensure_app_wallet_authorized(&self) -> Result<AppAuthzContext> {
        if !self.use_app_wallet {
            bail!("app wallet integration is disabled");
        }

        let material = self.resolve_app_wallet_material().await?;
        let instance_wallet = match self.local_eth_address().await {
            Ok(wallet) => wallet,
            Err(local_err) => {
                warn!(
                    "Failed to resolve local instance wallet for app wallet context; using app wallet address: {}",
                    local_err
                );
                material.address.clone()
            }
        };

        Ok(AppAuthzContext {
            // App-wallet APIs currently run in enclave-local mode and do not depend on
            // registry-based app/instance authorization.
            app_id: 0,
            app_wallet: material.address.clone(),
            instance_wallet,
        })
    }

    pub async fn app_wallet_key(&self) -> Result<EthKey> {
        if !self.use_app_wallet {
            bail!("app wallet integration is disabled");
        }

        let material = self.resolve_app_wallet_material().await?;
        EthKey::new_from_bytes(&material.private_key_hex)
            .map_err(|err| anyhow!("invalid app wallet private key material in KMS: {}", err))
    }

    pub async fn app_wallet_address(&self) -> Result<String> {
        if !self.use_app_wallet {
            bail!("app wallet integration is disabled");
        }

        Ok(self.resolve_app_wallet_material().await?.address.clone())
    }

    async fn resolve_app_wallet_material(&self) -> Result<AppWalletMaterial> {
        if let Some(cached) = self.cached_app_wallet_material().await {
            return Ok(cached);
        }

        let mut private_key_b64 = self.kv_get(APP_WALLET_KV_PRIVATE_KEY).await?;
        let mut address_b64 = self.kv_get(APP_WALLET_KV_ADDRESS).await?;

        if private_key_b64.is_none() && address_b64.is_none() {
            let generated = EthKey::new();
            let generated_private_key_hex = generated.private_key_hex_zeroizing();
            let generated_address = canonical_wallet(&generated.address())?;
            self.write_app_wallet_record(generated_private_key_hex.as_str(), &generated_address)
                .await?;

            // Re-read and require the persisted value to match the locally initialized
            // wallet material before exposing app-wallet APIs.
            private_key_b64 = self.kv_get(APP_WALLET_KV_PRIVATE_KEY).await?;
            address_b64 = self.kv_get(APP_WALLET_KV_ADDRESS).await?;

            let private_key_b64 = private_key_b64.as_deref().ok_or_else(|| {
                anyhow!("KMS app wallet is incomplete: missing private key record")
            })?;
            let address_b64 = address_b64
                .as_deref()
                .ok_or_else(|| anyhow!("KMS app wallet is incomplete: missing address record"))?;
            let material = Self::decode_app_wallet_material(private_key_b64, address_b64)?;
            if material.private_key_hex != generated_private_key_hex.as_str()
                || material.address != generated_address
            {
                bail!(
                    "app wallet unavailable: KMS app wallet material does not match local initialization"
                );
            }
            self.cache_app_wallet_material(material.clone()).await;
            return Ok(material);
        }

        let private_key_b64 = private_key_b64
            .as_deref()
            .ok_or_else(|| anyhow!("KMS app wallet is incomplete: missing private key record"))?;
        let address_b64 = address_b64
            .as_deref()
            .ok_or_else(|| anyhow!("KMS app wallet is incomplete: missing address record"))?;
        let material = Self::decode_app_wallet_material(private_key_b64, address_b64)?;
        self.cache_app_wallet_material(material.clone()).await;
        Ok(material)
    }

    fn decode_app_wallet_material(
        private_key_b64: &str,
        address_b64: &str,
    ) -> Result<AppWalletMaterial> {
        let private_key_hex = decode_kms_private_key_hex(private_key_b64)?;
        let local_key = EthKey::new_from_bytes(&private_key_hex)
            .map_err(|err| anyhow!("invalid app wallet private key material in KMS: {}", err))?;
        let local_address = canonical_wallet(&local_key.address())?;
        let kms_address = decode_kms_wallet_address(address_b64)?;
        if kms_address != local_address {
            bail!(
                "app wallet unavailable: KMS address {} does not match local address {}",
                kms_address,
                local_address
            );
        }
        Ok(AppWalletMaterial {
            private_key_hex,
            address: local_address,
        })
    }

    async fn write_app_wallet_record(&self, private_key_hex: &str, address: &str) -> Result<()> {
        let mut private_key_bytes = hex::decode(trim_0x(private_key_hex))
            .map_err(|err| anyhow!("invalid app wallet private key hex: {}", err))?;
        let mut private_key_b64 = general_purpose::STANDARD.encode(&private_key_bytes);
        private_key_bytes.zeroize();
        self.kv_put(APP_WALLET_KV_PRIVATE_KEY, &private_key_b64, 0)
            .await?;
        private_key_b64.zeroize();
        self.write_app_wallet_address(address).await
    }

    async fn write_app_wallet_address(&self, address: &str) -> Result<()> {
        let canonical = canonical_wallet(address)?;
        let address_b64 = general_purpose::STANDARD.encode(canonical.as_bytes());
        self.kv_put(APP_WALLET_KV_ADDRESS, &address_b64, 0).await
    }

    async fn cache_app_wallet_material(&self, material: AppWalletMaterial) {
        let expires_at_ms = current_unix_millis().saturating_add(APP_WALLET_CACHE_TTL_MS);
        let mut guard = self.app_wallet_cache.write().await;
        *guard = Some(CachedAppWallet {
            material,
            expires_at_ms,
        });
    }

    async fn cached_app_wallet_material(&self) -> Option<AppWalletMaterial> {
        let now_ms = current_unix_millis();
        let guard = self.app_wallet_cache.read().await;
        if let Some(cached) = guard.as_ref()
            && now_ms < cached.expires_at_ms
        {
            return Some(cached.material.clone());
        }
        drop(guard);
        let mut write_guard = self.app_wallet_cache.write().await;
        *write_guard = None;
        None
    }
}
