//! Explicit internet diagnostic, separate from deterministic OS security tests.
#![cfg(target_os = "macos")]
use runboundary::{
    policy::{config::Config, matcher::Matcher},
    sandbox::{backend::Backend, process},
    security::paths::Dir,
    workspace::prepare,
};
use std::{path::PathBuf, process::Command};

const DNS: &str = r#"
(allow mach-lookup
 (global-name "com.apple.SystemConfiguration.DNSConfiguration")
 (global-name "com.apple.SystemConfiguration.NetworkInformation")
 (global-name "com.apple.dnssd.service"))
"#;
const DNS_SOCKET: &str = r#"
(allow network-outbound (literal "/private/var/run/mDNSResponder"))
"#;
const CONTROL: &str = r#"
(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))
(allow network-outbound (control-name "com.apple.netsrc"))
"#;
const TLS: &str = r#"
(allow mach-lookup (global-name "com.apple.trustd")
 (global-name "com.apple.trustd.agent") (global-name "com.apple.networkd"))
"#;
const NETWORK_QUERY: &str = r#"
(allow sysctl-read (sysctl-name-prefix "net."))
(allow system-info (info-type "net.link.addr"))
(allow system-socket (socket-domain AF_ROUTE))
"#;
const NODE_DNS: &str = r#"
const timer=setTimeout(()=>{console.log(JSON.stringify({stage:'dns',error:'timeout'}));process.exit(1)},7000);
require('dns').lookup('api.openai.com',(e)=>{clearTimeout(timer);console.log(JSON.stringify({stage:'dns',ok:!e,error:e?e.code:null}));process.exit(e?1:0)});
"#;
const NODE_FILES: &str = r#"
const fs=require('fs');
for(const path of ['/etc/resolv.conf','/private/etc/resolv.conf','/private/var/run/resolv.conf','/etc/hosts','/private/etc/hosts','/etc/services','/private/etc/ssl/openssl.cnf']){
 try{const fd=fs.openSync(path,'r');fs.closeSync(fd);console.log(JSON.stringify({stage:'file-open',path,ok:true}));}
 catch(e){console.log(JSON.stringify({stage:'file-open',path,error:e.code}));}
}
for(const path of ['/etc/resolv.conf','/private/etc/resolv.conf']){
 try{fs.readlinkSync(path);console.log(JSON.stringify({stage:'resolver-readlink',path,ok:true}));}
 catch(e){console.log(JSON.stringify({stage:'resolver-readlink',path,error:e.code}));}
}
"#;
const NODE_HTTPS: &str = r#"
const timer=setTimeout(()=>{console.log(JSON.stringify({stage:'https',error:'timeout'}));process.exit(1)},12000);
const req=require('https').get('https://api.openai.com/v1/models',res=>{
 clearTimeout(timer);console.log(JSON.stringify({stage:'https',http_status:res.statusCode}));res.destroy();
});
req.on('error',e=>{clearTimeout(timer);console.log(JSON.stringify({stage:'https',error:e.code||e.name}));process.exit(1)});
"#;

#[test]
#[ignore = "REAL internet diagnostic: requires Terminal and approved Node.js; no API key used"]
fn diagnose_macos_provider_network() {
    let project = tempfile::tempdir().unwrap();
    let mut config = Config::for_host();
    config.sandbox.runtime_roots.push(PathBuf::from(
        std::env::var_os("RUNBOUNDARY_TEST_RUNTIME_ROOT")
            .expect("explicit runtime approval is required"),
    ));
    let backend = Backend::select(project.path(), &config).unwrap();
    let matcher = Matcher::new(&config).unwrap();
    let work = prepare::prepare(&Dir::open(project.path()).unwrap(), &matcher).unwrap();
    let env = backend.environment(&config, &[], work.path()).unwrap();
    assert!(!env.contains_key("OPENAI_API_KEY"));
    backend.probe(project.path(), work.path(), &env).unwrap();
    let node = backend.resolve("node").unwrap();
    let curl = backend.resolve("/usr/bin/curl").unwrap();
    // -q forbids ~/.curlrc; no credentials, cookies, response bodies or proxy
    // values are sent/read/printed. HTTP 401 is useful successful connectivity.
    let probes = [
        (
            "resolver-files",
            node.clone(),
            vec!["-e".into(), NODE_FILES.into()],
        ),
        ("node-dns", node.clone(), vec!["-e".into(), NODE_DNS.into()]),
        ("node-https", node, vec!["-e".into(), NODE_HTTPS.into()]),
        (
            "system-curl-https",
            curl,
            [
                "-q",
                "--noproxy",
                "*",
                "--connect-timeout",
                "5",
                "--max-time",
                "12",
                "--silent",
                "--show-error",
                "--output",
                "/dev/null",
                "--write-out",
                "{\"http_status\":\"%{http_code}\"}\n",
                "https://api.openai.com/v1/models",
            ]
            .map(String::from)
            .to_vec(),
        ),
    ];
    for variable in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        println!(
            "Host {variable} present (value withheld): {}",
            std::env::var_os(variable).is_some()
        );
    }
    let all = format!("{DNS}{DNS_SOCKET}{CONTROL}{TLS}{NETWORK_QUERY}");
    let variants = [
        ("host-clean-environment", "".to_owned()),
        ("production-profile", "".to_owned()),
        ("historical-no-dns-socket", "".to_owned()),
        ("dns-mach-only", DNS.to_owned()),
        ("dns-socket-only", DNS_SOCKET.to_owned()),
        ("dns-mach-and-control", format!("{DNS}{CONTROL}")),
        ("tls-brokers-only", TLS.to_owned()),
        ("network-query-only", NETWORK_QUERY.to_owned()),
        ("combined-network-support", all),
    ];
    let mut host_ok = 0;
    let mut production_ok = 0;
    let mut sandbox_pids = Vec::new();
    for (variant, rules) in variants {
        for (name, executable, args) in &probes {
            println!("RUNNING {variant}/{name}");
            let mut command = if variant == "host-clean-environment" {
                let mut c = Command::new(executable);
                c.args(args).env_clear().envs(&env).current_dir(work.path());
                process::harden(&mut c);
                c
            } else {
                let base = backend
                    .command(project.path(), work.path(), &env, executable, args)
                    .unwrap();
                let mut c = Command::new(base.get_program());
                c.env_clear().envs(&env).current_dir(work.path());
                let mut profile_next = false;
                for arg in base.get_args() {
                    if profile_next {
                        let mut source = arg.to_str().unwrap().to_owned();
                        if variant != "production-profile" {
                            // Candidate comparisons reproduce the previous DNS
                            // failure; production itself is tested unchanged.
                            source =
                                source.replace("(literal \"/private/var/run/mDNSResponder\")", "");
                        }
                        // Preserve the verified final process-data restriction
                        // after every candidate's additional networking grants.
                        if rules.is_empty() {
                            c.arg(source);
                        } else {
                            c.arg(format!("{source}\n{rules}\n(deny process-info*)\n"));
                        }
                        profile_next = false;
                    } else {
                        c.arg(arg);
                        profile_next = arg == "-p";
                    }
                }
                process::harden(&mut c);
                c
            };
            command
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let child = command.spawn().unwrap();
            if variant != "host-clean-environment" {
                sandbox_pids.push(child.id());
            }
            let output = child.wait_with_output().unwrap();
            let stdout: String = String::from_utf8_lossy(&output.stdout)
                .chars()
                .take(4096)
                .collect();
            let stderr: String = String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(4096)
                .collect();
            println!(
                "{variant}/{name}: status={}, stdout={stdout:?}, stderr={stderr:?}",
                output.status
            );
            if output.status.success() {
                if variant == "host-clean-environment" {
                    host_ok += 1;
                }
                if variant == "production-profile" {
                    production_ok += 1;
                }
            }
        }
    }
    // Read-only, best-effort evidence restricted to our unauthenticated probe
    // PIDs. macOS may suppress reporting; missing logs never count as success.
    let selected_pids = sandbox_pids
        .iter()
        .map(|pid| format!("eventMessage CONTAINS \"({pid})\""))
        .collect::<Vec<_>>()
        .join(" OR ");
    let predicate = format!("(process == \"kernel\" OR process == \"sandboxd\" OR subsystem BEGINSWITH \"com.apple.sandbox\") AND ({selected_pids})");
    println!("Collecting best-effort macOS denial records for diagnostic PIDs only");
    match Command::new("/usr/bin/log")
        .args([
            "show",
            "--last",
            "5m",
            "--style",
            "compact",
            "--info",
            "--debug",
            "--predicate",
            &predicate,
        ])
        .env_clear()
        .output()
    {
        Ok(output) => {
            let stdout: String = String::from_utf8_lossy(&output.stdout)
                .chars()
                .take(65536)
                .collect();
            let stderr: String = String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(4096)
                .collect();
            println!(
                "denial-record lookup: status={}, stdout={stdout:?}, stderr={stderr:?}",
                output.status
            );
        }
        Err(error) => println!("denial records unavailable: {error}"),
    }
    assert_eq!(host_ok, probes.len(), "host clean-environment baseline failed; check network, mandatory proxy or CA requirements before attributing failures to Seatbelt");
    assert_eq!(production_ok, probes.len(), "production provider connectivity failed; compare candidate results above. No production permissions were changed by this diagnostic");
}
