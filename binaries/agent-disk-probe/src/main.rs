//! `hippius-agent-disk-probe`: run the probe request, if there is one.
//!
//! Exit 0 when there is no request (dormant) or the result is written;
//! 1 on an unusable request or an unwritable result (logged by class).

use std::time::Duration;

use hippius_agent_disk_probe::profiles::Timing;
use hippius_agent_disk_probe::request::{Request, REQUEST_PATH};
use hippius_agent_disk_probe::result::{self, Host};

const RESULT_PATH: &str = "/run/hippius/disk-probe/result.cbor";

fn main() -> std::process::ExitCode {
    // Up to 30 s for a request the path unit saw created but not yet
    // written (the unit's `-` prefix means a refusal is not retried).
    let req = match Request::load_settled(
        std::path::Path::new(REQUEST_PATH),
        30,
        Duration::from_secs(1),
    ) {
        Ok(Some(req)) => req,
        Ok(None) => return std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hippius-agent-disk-probe: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if std::path::Path::new(RESULT_PATH).exists() {
        // Done already this boot: a restart does not run it twice.
        return std::process::ExitCode::SUCCESS;
    }
    std::thread::sleep(Duration::from_secs(req.start_delay_s));
    let result = result::run(&req, &Host::production(), &Timing::PRODUCTION);
    match result::write(&result, std::path::Path::new(RESULT_PATH)) {
        Ok(()) => {
            eprintln!(
                "hippius-agent-disk-probe: {} target(s) probed",
                result.targets.len()
            );
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("hippius-agent-disk-probe: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
