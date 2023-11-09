///
/// Run this example with:
/// cargo run --all-features --example client_exec_simple -- -k <private key path> <host> <command>
///
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use log::info;
use russh::*;
use russh_keys::*;
use std::io::Write;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::ToSocketAddrs;

const FILE_LEN: usize = 1024 * 1024 * 10; // 10MB

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    // CLI options are defined later in this file
    let cli = Cli::parse();

    info!("Connecting to {}:{}", cli.host, cli.port);
    info!("Key path: {:?}", cli.private_key);

    // Session is a wrapper around a russh client, defined down below
    let mut ssh = Session::connect(
        cli.private_key,
        cli.username.unwrap_or("root".to_string()),
        (cli.host, cli.port),
    )
    .await?;
    info!("Connected");

    for i in 0..50 {
        ssh.push_file_from_bytes(&vec![0; FILE_LEN], "foo").await;
        let wc_out = ssh.call("wc -c foo").await.unwrap().trim().to_owned();
        println!("attempt #{i} {wc_out}");
        let length: usize = wc_out.split_whitespace().next().unwrap().parse().unwrap();

        assert_eq!(length, FILE_LEN);
    }

    ssh.close().await?;
    Ok(())
}

struct Client {}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        self,
        _server_public_key: &key::PublicKey,
    ) -> Result<(Self, bool), Self::Error> {
        Ok((self, true))
    }
}

/// This struct is a convenience wrapper
/// around a russh client
pub struct Session {
    session: client::Handle<Client>,
}

impl Session {
    async fn connect<P: AsRef<Path>, A: ToSocketAddrs>(
        key_path: P,
        user: impl Into<String>,
        addrs: A,
    ) -> Result<Self> {
        let key_pair = load_secret_key(key_path, None)?;
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            ..<_>::default()
        };

        let config = Arc::new(config);
        let sh = Client {};

        let mut session = client::connect(config, addrs, sh).await?;
        let auth_res = session
            .authenticate_publickey(user, Arc::new(key_pair))
            .await?;

        if !auth_res {
            anyhow::bail!("Authentication failed");
        }

        Ok(Self { session })
    }

    async fn call(&mut self, command: &str) -> Result<String> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut stdout = vec![];
        let mut stderr = vec![];

        loop {
            // There's an event available on the session channel
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                // Write data to the terminal
                ChannelMsg::Data { ref data } => {
                    Write::write_all(&mut stdout, data)?;
                }
                ChannelMsg::ExtendedData { data, ext } => {
                    if ext == 1 {
                        Write::write_all(&mut stderr, &data).unwrap()
                    } else {
                        println!(
                            "received unknown extended data with extension type {ext} containing: {:?}",
                            data.to_vec()
                        )
                    }
                }
                // The command has returned an exit code
                ChannelMsg::ExitStatus { exit_status } => {
                    assert_eq!(exit_status, 0);
                    channel.eof().await?;
                    break;
                }
                ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    ..
                } => panic!(
                    "killed via signal {:?} core_dumped={} {:?}",
                    signal_name, core_dumped, error_message
                ),
                _ => {}
            }
        }
        if !stderr.is_empty() {
            panic!("stderr:{}", String::from_utf8(stderr).unwrap())
        }
        Ok(String::from_utf8(stdout).unwrap())
    }

    async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }

    /// Create a file on the remote machine at `dest` with the provided bytes.
    pub async fn push_file_from_bytes(&self, bytes: &[u8], dest: &str) {
        let source = BufReader::new(bytes);
        self.push_file_impl(source, dest).await;
    }

    async fn push_file_impl<R: AsyncReadExt + Unpin>(&self, source: R, dest: &str) {
        let mut channel = self.session.channel_open_session().await.unwrap();
        let command = format!("rm {0}\ncat > '{0}'\nchmod 777 {0}", dest);
        channel.exec(true, command).await.unwrap();

        let mut stdout = vec![];
        let mut stderr = vec![];
        let mut status = None;
        let mut failed = None;
        channel.data(source).await.unwrap();
        channel.eof().await.unwrap();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => Write::write_all(&mut stdout, &data).unwrap(),
                ChannelMsg::ExtendedData { data, ext } => {
                    if ext == 1 {
                        Write::write_all(&mut stderr, &data).unwrap()
                    } else {
                        println!(
                            "received unknown extended data with extension type {ext} containing: {:?}",
                            data.to_vec()
                        )
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    status = Some(exit_status);
                    // cant exit immediately, there might be more data still
                }
                ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    ..
                } => {
                    failed = Some(format!(
                    "killed via signal {signal_name:?} core_dumped={core_dumped} {error_message:?}"
                ))
                }
                _ => {}
            }
        }

        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();

        if let Some(failed) = failed {
            panic!("{}\n{}\n{}", failed, stdout, stderr)
        }

        match status {
            Some(status) => {
                if status != 0 {
                    panic!("failed with exit code {}\n{}\n{}", status, stdout, stderr)
                }
            }
            None => panic!("did not exit cleanly\n{}\n{}", stdout, stderr),
        }
    }
}

#[derive(clap::Parser)]
#[clap(trailing_var_arg = true)]
pub struct Cli {
    #[clap(index = 1)]
    host: String,

    #[clap(long, short, default_value_t = 22)]
    port: u16,

    #[clap(long, short)]
    username: Option<String>,

    #[clap(long, short = 'k')]
    private_key: PathBuf,
}
