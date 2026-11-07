//! The serving path: the per-core async fleet, until the caller flips `shutdown`.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::async_serve::ServedHttpRequest;
use crate::clock::now_unix;
use crate::HttpProfileProxy;

/// ADR-MCPRE-051 §1/§3 — serve on the per-core async fleet forwarding over the
/// pooled HTTP inner plane. Built when `--inner-http-url` is set; the sync stdio
/// serving path is used otherwise.
///
/// Consumes the fully-built `proxy` (adds the async replay tier + async HTTP inner
/// to it), binds one `SO_REUSEPORT` listener per core, and serves
/// `Proxy::handle_with_transport_async` on each core's own tokio runtime until a
/// SIGTERM/SIGINT drains the fleet within the bounded grace window.
///
/// The authoritative replay tier and async HTTP inner have already been wired into
/// `proxy` by the caller.
///
/// # This function owns no teardown obligation
///
/// It borrows the proxy through an `Arc` and returns once `fleet.shutdown_and_join()` has
/// returned, which is the DRAIN: no request can be in flight afterwards. Everything that
/// must then happen in a particular order — each plane's post-owner transition, and
/// reclaiming the control runtime the proxy's networked clients are bound to — belongs to
/// [`crate::materialized_runtime::MaterializedRuntime`], the sole issuer of `authorized` and
/// so the only caller, which tears down after. The drain here and the ordering there is
/// deliberate: this function's contract is "no request is running when I return", and
/// that is all a caller should have to know to sequence anything after it.
pub(crate) fn serve_fleet(
    proxy: Arc<HttpProfileProxy>,
    serving: crate::materialized_runtime::FleetServing,
    authorized: crate::materialized_runtime::fleet_serve_authorized::FleetServeAuthorized,
) -> Result<(), String> {
    // MCPRE-116: hand the fleet the SNAPSHOT, not a one-shot `load()`. The accept
    // loop re-reads it per connection, so the CRL hot-reload task's atomic swap is
    // observed by the next handshake instead of being written to a config nothing
    // reads again.
    let server_config = Arc::clone(&serving.config_snapshot);
    // The caller owns the shutdown flag (the binary wires it to SIGTERM/SIGINT; a
    // test flips it directly). We hand a clone to the fleet and poll the same flag.

    // One handler per core over the SHARED `Proxy` (Send + Sync, MCPRE-111); each
    // request awaits the async replay tier + async HTTP inner without blocking the
    // per-core runtime worker.
    let handler_proxy = Arc::clone(&proxy);
    let make_handler = move |_core: usize| {
        let proxy = Arc::clone(&handler_proxy);
        Arc::new(
            move |req: ServedHttpRequest| -> crate::async_serve::HandlerResponseFuture {
                let proxy = Arc::clone(&proxy);
                Box::pin(async move { proxy.handle(req, now_unix()).await })
            },
        )
    };

    let fleet = crate::async_fleet::serve_fleet(
        authorized.into_fleet_config(),
        server_config,
        serving.serve_options,
        make_handler,
        Arc::clone(&serving.shutdown),
    )
    .map_err(|e| format!("start async fleet: {e}"))?;
    eprintln!(
        "mcp-re-proxy: async fleet serving on {} ({} per-core workers)",
        fleet.local_addr(),
        fleet.worker_count(),
    );

    // Block until the caller flips `shutdown`, then drain the fleet (bounded).
    while !serving.shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!("mcp-re-proxy: shutdown signal received; draining async fleet");
    fleet.shutdown_and_join();
    eprintln!("mcp-re-proxy: async fleet drained, exiting cleanly");
    Ok(())
}
