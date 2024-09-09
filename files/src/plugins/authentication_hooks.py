from typing import Callable, Optional

from django.http import HttpRequest, HttpResponseBase

from custom_py.src.types import models as types_models, request as types_request
from custom_py.src.types import models_extension as types_models_ext

hooks = [
    types_models.MiddlewareHook.revalidateAuthentication.value,
    types_models.MiddlewareHook.mutatingPostAuthentication.value,
    types_models.MiddlewareHook.postAuthentication.value,
    types_models.MiddlewareHook.postLogout.value
]


def handler(module: types_request.register_module) -> Optional[Callable[[HttpRequest], HttpResponseBase]]:
    def wrapper(request: HttpRequest) -> HttpResponseBase:
        if request.method != "POST":
            return types_request.make_hook_error_response("Method {} Not Allowed".format(request.method))
        try:
            request_ctx = types_request.make_base_request_context(request)
            if request_ctx.internal_client.user is None:
                return types_request.make_hook_error_response("User not found")
            output_data = module.attr(request_ctx)
            return types_request.make_json_response(types_models.MiddlewareHookResponse(
                hook=types_models_ext.get_enum_by_value(types_models.MiddlewareHook, module.name),
                response=output_data.to_json() if output_data else {},
                setClientRequestHeaders=request_ctx.internal_client.clientRequest.headers.to_json()
            ))
        except Exception as e:
            return types_request.make_hook_error_response(e)

    return wrapper
