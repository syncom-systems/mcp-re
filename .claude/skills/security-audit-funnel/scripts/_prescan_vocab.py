"""Shared vocabulary of the structural pre-scan: roles, skipped directories and the
Python and Rust patterns every pass matches against."""

import re

# Roles excluded from the production structural floor (tooling / non-shipped).
NON_PROD_ROLES = {"test", "generated", "script", "migration"}

# Directories that never hold first-party source: build output, VCS metadata,
# and vendored/third-party dependency trees. Also skipped: any `.venv*` and any
# `bazel-*` convenience symlink (handled at the walk site).
VENDOR_DIRS = {
    "target", ".git", "__pycache__", "node_modules", "venv", "env",
    "site-packages", "dist-packages", "vendor", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", ".bazel", "bazel-out",
}

SECURITY_HINT = re.compile(
    r"(verify|sign|signature|auth|trust|resolver|replay|nonce|token|cert|tls|mtls"
    r"|crypt|key|policy|binding|admission|revoc|freshness|canonical|principal|tenant)",
    re.IGNORECASE,
)

# ---- Python (service composition-root model, from the original prescan) ------ #
PY_WIREABLE = re.compile(
    r"(Service|Handler|Persister|Consumer|ConsumerLoop|Loop|Publisher|Projector"
    r"|Bridge|Writer|Janitor|Coordinator|Dispatcher|Processor|Worker|Listener"
    r"|Subscriber|Producer|Sink|Pipeline|Gateway|Reconciler|Scheduler|Poller"
    r"|Verifier|Resolver|Emitter|Forwarder|Relay)$"
)
PY_NOOP = re.compile(r"^(Noop|NoOp|Null|Dummy|Fake|Stub|InMemory)")
PY_COMPROOT_NAMES = {
    "dependencies.py", "container_config.py", "container.py", "main.py",
    "app.py", "application.py", "wiring.py", "composition.py", "bootstrap.py",
    "startup.py", "server.py",
}
PY_COMPROOT_HINT = re.compile(
    r"(def lifespan|@asynccontextmanager|def build_container|build_container\s*\("
    r"|def create_app|create_app\s*\(|FastAPI\s*\(|def register_dependencies)")
PY_AUTH_MARKERS = re.compile(
    r"(add_middleware\([^)]*[Aa]uth|AuthenticationMiddleware|AuthMiddleware"
    r"|require_scope|require_auth|Depends\([^)]*[Aa]uth|HTTPBearer|OAuth2"
    r"|security_scopes|token_verifier|verify_bearer)")
PY_AUTH_FILE_HINT = re.compile(r"(middleware|auth|security)", re.IGNORECASE)
# Composition-root-wide inbound-auth / PEP wiring signals. Unlike PY_AUTH_MARKERS
# (which is gated behind a middleware/auth/security FILE-NAME hint), these are
# recognised anywhere in the comproot set — a service routinely wires its inbound
# PEP from `main.py`/`app.py`, not from a file literally named `*auth*`. Any one
# of these is sufficient evidence that inbound authentication is installed:
#   - a resource-server PEP install / object (install_resource_server, ResourceServer)
#   - a per-route scope guard (require_scope(...))
#   - an auth/verification/scope middleware added via add_middleware(...)
#   - a bearer/token validator install
PY_INBOUND_AUTH_WIRING = re.compile(
    r"(install_resource_server|\bResourceServer\b|\bresource_server\b"
    r"|require_scope\s*\(|require_auth\s*\("
    r"|add_middleware\s*\(\s*[A-Za-z_][\w.]*"
    r"(?:Auth|Authentication|Scope|Verification|Bearer|Token|Security|PEP)[\w.]*"
    r"|AuthenticationMiddleware|AuthMiddleware|VerificationMiddleware|ScopeMiddleware"
    r"|build_token_validator|token_validator|HTTPBearer|OAuth2|verify_bearer)")
PY_ENDPOINT_MARKERS = re.compile(
    r"(APIRouter|include_router|add_api_route|@router\.|@app\.(get|post|put|patch|delete)"
    r"|FastAPI\(|add_route|Starlette\()")
PY_LONG_RUNNER = re.compile(
    r"(Persister|Consumer|Loop|Janitor|Poller|Worker|Listener|Subscriber"
    r"|Scheduler|Reconciler)$")

# ---- Rust ------------------------------------------------------------------- #
RS_STUB = re.compile(r"\b(todo!|unimplemented!)\s*\(")
# `.expect(` requires a STRING-LITERAL argument to count as the panicking
# Result/Option::expect — this excludes parser-combinator / domain methods named
# `expect` that take a non-string (e.g. `self.expect(ch)?`).
RS_PANIC = re.compile(
    r"\.unwrap\(\)|\.expect\(\s*r?#*\"|\bpanic!\s*\(|\bunreachable!\s*\("
    r"|\bassert!\s*\(|\bassert_eq!\s*\(|\bassert_ne!\s*\(")
RS_UNSAFE = re.compile(r"\bunsafe\s*\{|\bunsafe\s+fn\b")
RS_SERVE = re.compile(r"\bTcpListener\b|\bfn\s+serve(?:_\w+)?\s*\(|\.accept\s*\(")
RS_VERIFY = re.compile(
    r"\bverify_request\b|\bverify_response\b|\bcheck_and_insert\b|\.resolve\s*\("
    r"|\bTransportBindingPolicy\b|\bbinding\.check\b|\.evaluate\s*\(")
RS_FN = re.compile(r"\bfn\s+([A-Za-z_]\w*)")
RS_NOOP_CTOR = re.compile(
    r"\b((?:InMemory|Noop|NoOp|Null|Dummy|Fake|Stub|Mock|Static|Always)\w*)\s*(::|\{)")
RS_SEC_IMPL = re.compile(
    r"\bimpl\b[^\n{]*\b(TrustResolver|ResponseSigner|KeySource|TransportBindingProvider"
    r"|ReplayCache|AtomicReplayStore|PolicyEvaluator|Verifier|Authorizer)\b\s+for\s+"
    r"([A-Za-z_]\w*)")

# `const _: () = { assert!(..) };` is a const-eval block: the assertions are checked by
# the compiler and cannot execute at runtime, so they are not a denial-of-service path.
# Masked (offsets preserved, so reported line numbers stay correct) rather than
# allowlisted, because no member of this category is ever a runtime panic.
RS_CONST_BLOCK = re.compile(r"\bconst\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*\(\s*\)\s*=\s*\{")

RS_TEST_ATTR = re.compile(r"#\[cfg\((?:all\()?test\b[^\]]*\]")
