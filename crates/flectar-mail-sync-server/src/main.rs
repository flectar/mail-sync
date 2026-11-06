use clap::{Parser, Subcommand};
use flectar_mail_sync_server::{Config, State, Store, app, run_maintenance};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(version, about = "Flectar Mail Sync server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    serve: ServeArgs,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the server (the default).
    Serve(ServeArgs),
    /// Exit 0 if the local server answers its health check (for containers).
    Healthcheck {
        #[arg(long, env = "FLECTAR_MAIL_SYNC_LISTEN", default_value = "0.0.0.0:8080")]
        listen: SocketAddr,
    },
    /// Write a consistent copy of the database to DESTINATION.
    Backup {
        #[arg(
            long,
            env = "FLECTAR_MAIL_SYNC_DATABASE",
            default_value = "/data/sync.db"
        )]
        database: PathBuf,
        destination: PathBuf,
    },
    /// Apply database migrations and exit.
    Migrate {
        #[arg(
            long,
            env = "FLECTAR_MAIL_SYNC_DATABASE",
            default_value = "/data/sync.db"
        )]
        database: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
struct ServeArgs {
    /// SQLite database file.
    #[arg(
        long,
        env = "FLECTAR_MAIL_SYNC_DATABASE",
        default_value = "/data/sync.db"
    )]
    database: PathBuf,
    /// Address to listen on.
    #[arg(long, env = "FLECTAR_MAIL_SYNC_LISTEN", default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
    /// The public URL devices use, e.g. https://sync.example.org. Login
    /// signatures are bound to it.
    #[arg(long, env = "FLECTAR_MAIL_SYNC_PUBLIC_URL")]
    public_url: Option<String>,
    /// Reader connections to the database.
    #[arg(long, env = "FLECTAR_MAIL_SYNC_READERS", default_value_t = 4)]
    readers: usize,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Healthcheck { listen }) => healthcheck(listen),
        Some(Command::Backup {
            database,
            destination,
        }) => run(async move {
            let store = Store::open(&database, 1)?;
            store.backup(destination).await?;
            Ok(())
        }),
        Some(Command::Migrate { database }) => run(async move {
            Store::open(&database, 1)?;
            Ok(())
        }),
        Some(Command::Serve(args)) => run(serve(args)),
        None => run(serve(cli.serve)),
    }
}

fn run(task: impl Future<Output = Result<(), Box<dyn std::error::Error>>>) -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("could not start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(task) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "exiting");
            ExitCode::FAILURE
        }
    }
}

async fn serve(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let public_url = args
        .public_url
        .ok_or("set FLECTAR_MAIL_SYNC_PUBLIC_URL (or --public-url) to the URL devices use")?;
    if let Some(parent) = args.database.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let store = Store::open(&args.database, args.readers)?;
    let state = State::new(Config::new(public_url), store);
    tokio::spawn(run_maintenance(state.clone()));
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(listen = %args.listen, "serving");
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("stopped");
    Ok(())
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}

/// A minimal HTTP/1.1 GET of /healthz on the loopback interface, so the
/// container image needs no curl.
fn healthcheck(listen: SocketAddr) -> ExitCode {
    let target = SocketAddr::from(([127, 0, 0, 1], listen.port()));
    let check = || -> std::io::Result<bool> {
        let timeout = Duration::from_secs(3);
        let mut stream = TcpStream::connect_timeout(&target, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut response = Vec::new();
        stream.take(64).read_to_end(&mut response)?;
        Ok(response.starts_with(b"HTTP/1.1 200"))
    };
    match check() {
        Ok(true) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}
