fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(
            &[
                "spire-api-sdk/proto/spire/api/server/agent/v1/agent.proto",
                "spire-api-sdk/proto/spire/api/server/entry/v1/entry.proto",
                "spire-api-sdk/proto/spire/api/server/bundle/v1/bundle.proto",
                "spire-api-sdk/proto/spire/api/server/svid/v1/svid.proto",
            ],
            &["spire-api-sdk/proto"],
        )?;

    let mut cfg = tonic_prost_build::Config::new();
    cfg.default_package_filename("workload");

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_with_config(
            cfg,
            &["spiffe/standards/workloadapi.proto"],
            &["go-spiffe/proto"],
        )?;
    Ok(())
}
