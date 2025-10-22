fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(
            &[
                "spire-api-sdk/proto/spire/api/server/agent/v1/agent.proto",
                "spire-api-sdk/proto/spire/api/server/entry/v1/entry.proto",
                "spire-api-sdk/proto/spire/api/server/svid/v1/svid.proto",
            ],
            &["spire-api-sdk/proto"],
        )?;
    Ok(())
}
