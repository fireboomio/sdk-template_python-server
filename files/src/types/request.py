import importlib
import json
import os
import time
from typing import Callable, Optional, Union

from django.http import HttpRequest, HttpResponse
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

    def to_dict(self) -> dict:
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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        return _dict


__wg_field_name = "__wg"
extra_header_keys = [types_models.InternalHeader.X_Request_Id.value, types_models.InternalHeader.uber_trace_id.value]


def make_base_request_context(request: HttpRequest) -> request_context:
    ctx = request_context(request, extraHeaders=types_models.RequestHeaders(
        {k: v for k, v in request.headers.items() if k in extra_header_keys}))
    body_json = json.loads(request.body)
    if __wg_field_name not in body_json:
        ctx.internal_client.clientRequest = types_models.WunderGraphRequest(
            headers=types_models.RequestHeaders(request.headers))
        return ctx
    body_wg = json_parser.parse_dict_to_class(body_json[__wg_field_name], types_models.BaseRequestBodyWg)
    ctx.internal_client.clientRequest = body_wg.clientRequest
    ctx.internal_client.user = body_wg.user
    return ctx


def make_hook_error_response(msg: Union[str, Exception]) -> HttpResponse:
    if isinstance(msg, Exception):
        msg = str(msg)
    return make_json_response(types_models.MiddlewareHookResponse(error=msg), status=400)


def make_json_response(data, **kwargs) -> HttpResponse:
    kwargs.setdefault("content_type", "application/json")
    return HttpResponse(json_parser.json_dumps(data), **kwargs)


health_report = types_models.HealthReport([], [], [])


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


def healthy(_: HttpRequest) -> HttpResponse:
    return make_json_response(types_models.Health(report=health_report, status="ok"))


urlpatterns = [path("health", healthy)]


class register_module:
    def __init__(self, folder: str, name: str, func: callable, import_):
        self.folder = folder
        self.name = name
        self.func = func
        self.import_ = import_


def register_views(folder: str,
                   handler: Callable[[register_module], Optional[Callable[[HttpRequest], HttpResponse]]],
                   allowed_hooks: list[str] = None, join_center: str = None):
    if not os.path.isdir(folder):
        return
    for item in os.listdir(folder):
        item_path = os.path.join(folder, item)
        if os.path.isdir(item_path):
            register_views(item_path, handler, allowed_hooks)
            continue
        if not item.endswith(".py"):
            continue
        item_without_ext = item.removesuffix(".py")
        if allowed_hooks is not None and item_without_ext not in allowed_hooks:
            continue
        item_module = importlib.import_module(item_path.removesuffix(".py").replace('/', '.'), package=".")
        if not hasattr(item_module, item_without_ext):
            continue
        item_prefix = os.path.join(folder, join_center) if join_center is not None else folder
        item_url = os.path.join(item_prefix, item).removesuffix(".py")
        handler_func = handler(register_module(folder, item_without_ext,
                                               getattr(item_module, item_without_ext), item_module))
        if handler_func is None:
            continue
        urlpatterns.append(path(item_url, handler_func))
        print(f"registered {item_url}")
