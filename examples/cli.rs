use anyhow::anyhow;
use clap::Parser;
use rc5_cypher::*;

#[derive(clap::Subcommand)]
enum Action {
    /// Cipher input according to rc5 code, with parameters 32/12/16
    Encode {
        /// Hex string repsenting plaintext
        #[arg(short, long)]
        plaintext: String,
    },
    /// Decipher input according to rc5 code, with parameters 32/12/16
    Decode {
        /// Hex string repsenting ciphertext
        #[arg(short, long)]
        ciphertext: String,
    },
}
impl Action {
    pub fn process(&self, key: impl rc5_cypher::Key) -> anyhow::Result<Vec<u8>> {
        Ok(match self {
            Self::Encode { plaintext } => {
                let plaintext = hex::decode(plaintext)?;

                if plaintext.len() <= DefaultWord::BYTES {
                    return Err(anyhow!(
                        "Please provide input longer than {bytes}",
                        bytes = DefaultWord::BYTES
                    ));
                }

                if plaintext.len() % DefaultWord::BYTES != 0 {
                    return Err(anyhow!(
                        "Please provide an input multiple of {bytes}",
                        bytes = DefaultWord::BYTES
                    ));
                }

                plaintext.encode_rc5(key)?
            }
            Self::Decode { ciphertext } => hex::decode(ciphertext)?.decode_rc5(key)?,
        })
    }
}

#[derive(clap::Parser)]
struct Args {
    /// Hex string representing 16 bytes key
    #[arg(short, long)]
    key: String,
    #[command(subcommand)]
    action: Action,
}

impl Args {
    pub fn key(&self) -> Result<secrecy::Secret<[u8; 16]>, anyhow::Error> {
        let key = hex::decode(&self.key)?;
        let key_len = key.len();
        Ok(secrecy::Secret::new(key.try_into().map_err(|_err| {
            anyhow!("Wrong key size {key_len} , expected 16")
        })?))
    }
}

fn main() -> anyhow::Result<()> {
    simple_logger::init().unwrap();

    let args = Args::parse();

    println!(
        "{}",
        hex::encode(
            args.action
                .process(args.key()?)
                .map_err(|err| anyhow!("Error while encode: {err:?}"))?,
        )
    );
    anyhow::Ok(())
}
