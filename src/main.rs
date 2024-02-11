use clap::Parser;
use serde_derive::{Serialize, Deserialize};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use std::fs::File;
use std::io::{self};

/// Structure to hold command-line arguments
#[derive(Parser, Serialize, Deserialize, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// Enable scanning with a specific IP address with the type of an IpAddr (example: -s 192.168.1.1)
    #[arg(short = 's', long = "scan")]
    scan: Option<IpAddr>,

    /// Specify the port range (example: "-p 1-1000")
    #[arg(short = 'p', long = "port")]
    port_range: Option<String>,

    /// Specify the timeout in seconds (example : -t <seconds>)
    #[arg(short = 't', long = "time", default_value = "2")]
    timeout: u64,

    /// Specify the output file (example : -o <Filename.json>)
    #[arg(short = 'o', long = "output")]
    output_file: Option<String>,
}

/// Structure to hold individual scan results
#[derive(Debug, Serialize)]
struct ScanResult {
    /// IP address of the scanned host
    ip: IpAddr,
    /// Port number that was scanned
    port: u16,
    /// Status of the port (OPEN or CLOSED)
    status: &'static str,
}

fn main() {
    // Parse command-line arguments
    let args = Args::parse();

    if let Some(scan_ip) = args.scan {
        println!("Scanning enabled for IP: {}", scan_ip);

        // Extract ports from the provided range argument
        let (start_port, end_port) = extract_ports(&args.port_range);

        // Run port scan and get results with custom timeout
        let results = run_port_scan(scan_ip, start_port, end_port, args.timeout);

        // Write results to the specified output file in JSON format
        if let Some(output_file) = &args.output_file {
            if let Err(err) = write_results_to_file(&results, output_file) {
                eprintln!("Error writing to file: {}", err);
            } else {
                println!("Results written to file: {}", output_file);
            }
        }
    }

    // Print additional information
    if let Some(port_range) = &args.port_range {
        println!("Port range specified: {}", port_range);
    }

    println!("Timeout specified: {} seconds", args.timeout);
}

/// Get the port range for the scan as a tuple
fn extract_ports(port_range: &Option<String>) -> (u16, u16) {
    if let Some(range) = port_range {
        let args: Vec<&str> = range.split('-').collect();

        if args.len() == 2 {
            if let (Ok(start), Ok(end)) = (args[0].parse(), args[1].parse()) {
                return (start, end);
            }
        }
    }
    // Default port range if not specified
    (1, 1024)
}

/// Run TCP scan with a custom timeout and return results
fn run_port_scan(ip_to_scan: IpAddr, start_port: u16, end_port: u16, timeout: u64) -> Vec<ScanResult> {
    let mut results = Vec::new();

    for port in start_port..=end_port {
        let target = SocketAddr::new(ip_to_scan, port);

        // Attempt to connect to the port within the specified timeout
        match TcpStream::connect_timeout(&target, Duration::from_secs(timeout)) {
            Ok(_) => results.push(ScanResult {
                ip: ip_to_scan,
                port,
                status: "OPEN",
            }),
            Err(_) => results.push(ScanResult {
                ip: ip_to_scan,
                port,
                status: "CLOSED",
            }),
        }
    }

    results
}

/// Write scan results to the specified output file in JSON format
fn write_results_to_file(results: &[ScanResult], filename: &str) -> io::Result<()> {
    let file = File::create(filename)?;
    serde_json::to_writer(file, &results).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ports() {
        assert_eq!(extract_ports(&Some("1-100".to_string())), (1, 100));
        assert_eq!(extract_ports(&Some("2000-3000".to_string())), (2000, 3000));
        assert_eq!(extract_ports(&Some("invalid".to_string())), (1, 1024));
        assert_eq!(extract_ports(&None), (1, 1024));
    }

    #[test]
    fn test_run_port_scan() {
        let results = run_port_scan(IpAddr::V4("127.0.0.1".parse().unwrap()), 80, 85, 2);
        assert_eq!(results.len(), 6);
    }
}
