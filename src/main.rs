use clap::{Parser, ValueEnum};

use color_eyre::eyre::eyre;
use color_eyre::eyre::Result;

use hickory_client::client::{Client, SyncClient};
use hickory_client::op::DnsResponse;
use hickory_client::rr::{DNSClass, Name, RecordType};
use hickory_client::tcp::TcpClientConnection;

use hickory_resolver::{error::ResolveErrorKind, Resolver};

use owo_colors::{OwoColorize, Stream::Stdout};

use regex::Regex;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// Check that all address records in a DNS zone have valid and acceptable PTR records associated
#[derive(Clone, Debug, Parser)]
#[command(
    author,
    version,
    about,
    long_about = None,
    help_template = "\
{before-help}{name} {version}
{author-with-newline}
{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
")]
struct Arguments {
    /// Regular expression for unacceptable PTRs
    #[clap(short, long)]
    badre: Option<String>,
    /// Use colored output
    #[clap(short, long, value_enum, default_value_t=Color::Auto)]
    color: Color,
    /// Server to do AXFR against (in form IP:port)
    #[arg(short, long)]
    server: String,
    /// Be more verbose
    #[arg(short, long)]
    verbose: bool,
    /// Zone to check PTR records for
    #[arg(short, long)]
    zone: String,
}

#[derive(ValueEnum, Clone, Debug)]
enum Color {
    Auto,
    Always,
    Never,
}

impl Color {
    fn init(self) {
        // Set a supports-color override based on the variable passed in.
        match self {
            Color::Always => owo_colors::set_override(true),
            Color::Auto => {}
            Color::Never => owo_colors::set_override(false),
        }
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Arguments::parse();
    args.clone().color.init();

    // If we got a badre set in the arguments then best compile it now, both for performance and to
    // check it's actually a valid regexp.
    let mut re = None;

    if let Some(badre) = &args.badre {
        match Regex::new(badre) {
            Ok(r) => {
                re = Some(r);
            }
            Err(_) => {
                return Err(eyre!("Invalid regex: {}", badre));
            }
        }
    }
    // match &args.badre {
    //     Some(badre) => match Regex::new(&badre) {
    //         Ok(r) => {
    //             re = Some(r);
    //         }
    //         Err(_) => {
    //             return Err(eyre!("Invalid regex: {}", badre));
    //         }
    //     },
    //     _ => {}
    // }

    let ip_port = args.server.clone();

    let address = ip_port.parse()?;
    let zone = Name::from_utf8(&args.zone)?;

    if args.verbose {
        println!(
            "Asking {} for AXFR of zone {}",
            ip_port.if_supports_color(Stdout, |t| t.cyan()),
            zone.if_supports_color(Stdout, |t| t.cyan())
        );
    }

    let seen_addresses = do_axfr(&args, address, zone)?;

    if args.verbose {
        let num_addr_records = seen_addresses.keys().len();
        println!(
            "Found {} unique address (A/AAAA) record{}",
            num_addr_records.if_supports_color(Stdout, |t| t.green()),
            if num_addr_records == 1 { "" } else { "s" }
        );
    }

    let mut failcount: u64 = 0;

    for (addr, names) in &seen_addresses {
        if args.verbose {
            list_names(addr, names);
        }

        if let Some(ptrnames) = get_ptrs(addr) {
            for ptr in ptrnames {
                // If a badre was supplied then need to check PTR against that. We compiled it
                // into `re` earlier.
                if let Some(r) = &re {
                    if let Some(_captures) = r.captures(&ptr) {
                        // This PTR matched the bad regex!
                        if !args.verbose {
                            list_names(addr, names);
                        }
                        println!(
                            "    {} '{}' for {} (matched regexp '{}')",
                            "Bad PTR content".if_supports_color(Stdout, |t| t.bright_red()),
                            ptr.if_supports_color(Stdout, |t| t.bright_red()),
                            addr.if_supports_color(Stdout, |t| t.cyan()),
                            r.as_str().if_supports_color(Stdout, |t| t.cyan())
                        );

                        failcount += 1;
                    }
                } else if args.verbose {
                    println!(
                        "    {}: {ptr}",
                        "Found PTR".if_supports_color(Stdout, |t| t.green())
                    );
                }
            }
        } else {
            // Now that we know there's a missing PTR we do want to see the names that point here.
            if !args.verbose {
                list_names(addr, names);
            }
            println!(
                "    {} for {}",
                "Missing PTR".if_supports_color(Stdout, |t| t.bright_red()),
                addr.if_supports_color(Stdout, |t| t.cyan())
            );

            failcount += 1;
        }
    }

    if failcount > 0 {
        let fire = emojis::get_by_shortcode("fire").unwrap();
        println!(
            "{} {} missing/broken PTR record{}",
            fire,
            failcount.if_supports_color(Stdout, |t| t.bright_red()),
            if failcount == 1 { "" } else { "s" }
        );
    }

    if args.verbose {
        let ok_pct: f32;
        let num_addr_records: usize = seen_addresses.keys().len();

        if num_addr_records > 0 {
            if failcount == 0 {
                ok_pct = 100.0;
            } else if failcount == num_addr_records as u64 {
                ok_pct = 0.0;
            } else {
                ok_pct =
                    (num_addr_records as f32 - failcount as f32) / num_addr_records as f32 * 100.0;
            }

            let sparkles = emojis::get_by_shortcode("sparkles").unwrap();
            let facepalm = emojis::get_by_shortcode("woman_facepalming").unwrap();
            let trophy = emojis::get_by_shortcode("trophy").unwrap();

            let badge = match ok_pct {
                100.0 => trophy,
                0.0 => facepalm,
                _ => sparkles,
            };

            println!(
                "{} {:.1}% good PTRs!{}",
                badge,
                ok_pct,
                if ok_pct == 100.0 { " Good job!" } else { "" }
            );
        }
    }

    if failcount > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn list_names(addr: &IpAddr, names: &[String]) {
    let right_arrow = "➡";
    println!(
        "{} {} is pointed to by:",
        right_arrow.if_supports_color(Stdout, |t| t.bright_cyan()),
        addr
    );
    println!("    {}", names.join(", "));
}

// Return an optional Vec of strings for the found PTR names. Usually there will be just one. If there's none,
// this will return None, not an empty Vec.
fn get_ptrs(addr: &IpAddr) -> Option<Vec<String>> {
    // Construct a new Resolver using system's resolv.conf.
    let resolver = Resolver::from_system_conf().unwrap();

    let mut ptrs = Vec::new();

    match resolver.reverse_lookup(*addr) {
        Ok(response) => {
            for name in response.iter() {
                ptrs.push(name.0.to_utf8());
            }
        }
        Err(e) => match e.kind() {
            ResolveErrorKind::NoRecordsFound { .. } => {
                // Empty answer, do nothing.
            }
            _ => {
                println!("    Unhandled resolver error: {e:?}");
            }
        },
    }

    if ptrs.is_empty() {
        // Don't return an emoty vec, return None.
        return None;
    }

    Some(ptrs)
}

fn do_axfr(
    args: &Arguments,
    address: SocketAddr,
    zone: Name,
) -> Result<HashMap<IpAddr, Vec<String>>> {
    let mut seen = HashMap::new();

    let conn = TcpClientConnection::new(address)?;
    let client = SyncClient::new(conn);

    let response: DnsResponse = match client.query(&zone, DNSClass::IN, RecordType::AXFR) {
        Ok(resp) => resp,
        Err(err) => {
            return Err(eyre!("Failed to create DNS query: {:?}", err));
        }
    };

    if !response.contains_answer() {
        return Err(eyre!("AXFR returned no answers: {response:?}"));
    }

    let answers = response.answers();

    if args.verbose {
        let num_records = answers.len();

        println!(
            "Zone contains {} record{}",
            num_records.if_supports_color(Stdout, |t| t.green()),
            if num_records == 1 { "" } else { "s" }
        );
    }

    let answers = answers
        .iter()
        .filter(|rec| matches!(rec.record_type(), RecordType::A | RecordType::AAAA));

    for record in answers {
        let rr_name = record.name().to_utf8();

        let rr_data = match record.data() {
            Some(data) => data,
            None => continue,
        };

        let rr_addr = match rr_data.ip_addr() {
            Some(addr) => addr,
            None => continue,
        };

        seen.entry(rr_addr).or_insert_with(Vec::new).push(rr_name);
    }

    Ok(seen)
}
