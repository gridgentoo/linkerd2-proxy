#![deny(warnings, rust_2018_idioms)]
#![forbid(unsafe_code)]
#![allow(clippy::inconsistent_struct_constructor)]

use anyhow::Result;
use structopt::StructOpt;

#[derive(Clone, Debug, StructOpt)]
enum Cmd {
    CreateCrds {
        #[structopt(long)]
        dry_run: bool,
    },
    ApplyCrds {
        #[structopt(long)]
        dry_run: bool,
    },
    DeleteCrds,
    Deploy(k8s_tests::deploy::Args),
    Runner(k8s_tests::runner::Args),
    Server(k8s_tests::server::Args),
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cmd = Cmd::from_args();
    let client = kube::Client::try_default().await?;
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    match cmd {
        Cmd::CreateCrds { dry_run } => k8s_tests::create_crds(client, TIMEOUT, dry_run).await,
        Cmd::ApplyCrds { dry_run } => k8s_tests::apply_crds(client, TIMEOUT, dry_run).await,
        Cmd::DeleteCrds => k8s_tests::delete_crds(client).await,
        Cmd::Runner(cmd) => cmd.run(client).await,
        Cmd::Server(cmd) => cmd.run().await,
        Cmd::Deploy(cmd) => cmd.run(client).await,
    }
}

fn init_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, registry, EnvFilter};

    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    registry().with(filter_layer).with(fmt::layer()).init()
}
