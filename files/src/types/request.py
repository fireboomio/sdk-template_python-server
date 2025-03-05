import importlib
import json
import logging
import os
import random
import time
import uuid
from functools import lru_cache
from typing import Callable, Optional, Union, Awaitable

from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.urls import path

from custom_py.src.types import models as types_models
from custom_py.src.utils import json_parser


class internal_client(types_models.BaseRequestBodyWg):
    def __init__(self,
                 extraHeaders: types_models.RequestHeaders = None,
                 clientRequest: types_models.WunderGraphRequest = None,
                 user: types_models.User = None):
        self.extraHeaders = extraHeaders
        super().__init__(clientRequest, user)

    def to_json(self) -> dict:
        _dict = self.__dict__.copy()
        return _dict


class request_context:
    def __init__(self,
                 request: HttpRequest,
                 extraHeaders: types_models.RequestHeaders = None,
                 clientRequest: types_models.WunderGraphRequest = None,
                 user: types_models.User = None):
        self.request = request
        self.internal_client = internal_client(extraHeaders, clientRequest, user)

    def to_json(self) -> dict:
        _dict = self.__dict__.copy()
        return _dict


def new_empty_internal_client():
    random.seed(time.time_ns())
    rand_number = random.getrandbits(63)
    uber_trace_id = f"{rand_number:016x}:{rand_number:016x}:0000000000000000:1"
    return internal_client(
        clientRequest=types_models.WunderGraphRequest(headers=types_models.RequestHeaders()),
        extraHeaders=types_models.RequestHeaders(**{
            types_models.InternalHeader.X_Request_Id.value: str(uuid.uuid4()),
            types_models.InternalHeader.uber_trace_id.value: uber_trace_id
        })
    )


__wg_field_name = "__wg"
extra_header_keys = [types_models.InternalHeader.X_Request_Id.value, types_models.InternalHeader.uber_trace_id.value]


def make_base_request_context(request: HttpRequest) -> request_context:
    ctx = request_context(request, extraHeaders=types_models.RequestHeaders(
        {k: v for k, v in request.headers.items() if k in extra_header_keys}))
    body_json = json.loads(request.body)
    if __wg_field_name in body_json:
        body_wg = json_parser.parse_dict_to_class(body_json[__wg_field_name], types_models.BaseRequestBodyWg)
        ctx.internal_client.user = body_wg.user
        ctx.internal_client.clientRequest = body_wg.clientRequest
    if not ctx.internal_client.clientRequest:
        ctx.internal_client.clientRequest = types_models.WunderGraphRequest(
            headers=types_models.RequestHeaders(request.headers))
    return ctx


def make_hook_error_response(msg: Union[str, Exception]) -> HttpResponse:
    if isinstance(msg, Exception):
        msg = str(msg)
        import traceback
        logging.error(traceback.format_exc())
    return make_json_response(types_models.MiddlewareHookResponse(error=msg), status=400)


def make_json_response(data, **kwargs) -> HttpResponse:
    kwargs.setdefault("content_type", "application/json")
    return HttpResponse(json_parser.json_dumps(data), **kwargs)


health_report = types_models.HealthReport([], [], [])
health_count = 0


def init_health_report_time():
    max_report_time = max([
        _get_max_time_from_list(types_models.HookParent.customize, health_report.customizes),
        _get_max_time_from_list(types_models.HookParent.function, health_report.functions),
        _get_max_time_from_list(types_models.HookParent.proxy, health_report.proxys),
    ])
    health_report.time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(max_report_time)) \
        if max_report_time > 0 else time.time()


def _get_max_time_from_list(prefix: types_models.HookParent, data: list[str]) -> float:
    data_times = [os.path.getmtime(os.path.join(prefix.value, x) + ".json") for x in data]
    return max(data_times) if len(data_times) > 0 else 0


def healthy(request: HttpRequest) -> HttpResponse:
    user_agent = request.headers.get("User-Agent", None)
    run_init_allowed = user_agent and user_agent.startswith("Go-http-client/")
    hook_report_value = request.GET.get('enable-hook-report', None)
    if hook_report_value:
        global health_count
        run_init_allowed = hook_report_value == "false" or health_count == 1
        if not run_init_allowed:
            health_count += 1
    if run_init_allowed:
        run_init_methods()
    return make_json_response(types_models.Health(report=health_report, status="ok", workdir=workdir))


urlpatterns = [path("health", healthy)]
init_methods = []
workdir = os.getcwd()


@lru_cache(maxsize=1)
def run_init_methods():
    for method in init_methods:
        method()


class register_module:
    def __init__(self, folder: str, name: str, url: str, attr: callable, import_):
        self.folder = folder
        self.name = name
        self.url = url
        self.attr = attr
        self.import_ = import_


def register_views(folder: str,
                   handler: Callable[
                       [register_module],
                       Optional[Callable[[HttpRequest], Union[HttpResponseBase, Awaitable[HttpResponseBase]]]]],
                   allowed_hooks: list[str] = None,
                   attr_name_suffix: str = ""):
    if not os.path.isdir(folder):
        return
    for item in os.listdir(folder):
        item_path = os.path.join(folder, item)
        if os.path.isdir(item_path):
            register_views(item_path, handler, allowed_hooks)
            continue
        if not item.endswith(".py") or item.startswith("__"):
            continue
        item_without_ext = item.removesuffix(".py")
        if allowed_hooks is not None and item_without_ext not in allowed_hooks:
            continue
        item_url = item_path.removesuffix(".py")
        if '\\' in item_url:
            item_url = item_url.replace('\\', '/')
        item_module_name = f"custom_py.{item_url.replace('/', '.')}"
        item_module = importlib.import_module(item_module_name)
        if not hasattr(item_module, item_without_ext + attr_name_suffix):
            continue
        if '\\' in folder:
            folder = folder.replace('\\', '/')
        item_attr = getattr(item_module, item_without_ext + attr_name_suffix)
        item_register_module = register_module(folder, item_without_ext, item_url, item_attr, item_module)
        handler_func = handler(item_register_module)
        if handler_func is None:
            continue

        item_register_module.url = item_register_module.url.removeprefix("/")
        urlpatterns.append(path(item_register_module.url, handler_func))
        print(f"registered {item_register_module.url}")
