use std::sync::Arc;

use anyhow::Result;
use log::info;
use rtnetlink::{LinkHandle, LinkUnspec};

use enclaver::nsm::Nsm;

const DEV_RANDOM: &str = "/dev/random";

pub async fn bootstrap(nsm: Arc<Nsm>) -> Result<()> {
    info!("Bringing up loopback interface");
    lo_up().await?;

    info!("Seeding {} with entropy from nsm device", DEV_RANDOM);
    seed_rng(&nsm)?;

    Ok(())
}

async fn lo_up() -> Result<()> {
    let (conn, handle, _receiver) = rtnetlink::new_connection()?;

    // this starts the background task of reading from the rtnetlink socket
    let conn_task = tokio::spawn(conn);

    // Assume that lo interface is one and only
    let result = LinkHandle::new(handle)
        .set(LinkUnspec::new_with_index(1).up().build())
        .execute()
        .await;

    // cancel the socket reading
    conn_task.abort();
    _ = conn_task.await;

    Ok(result?)
}

fn seed_rng(nsm: &Nsm) -> Result<()> {
    let seed = nsm.get_random()?;
    std::fs::write(DEV_RANDOM, seed)?;
    Ok(())
}
