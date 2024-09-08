from typing import Callable, Optional

from django.http import HttpRequest, HttpResponse

from custom_py.src.types import models as types_models, request as types_request
from custom_py.src.types import models_extension as types_models_ext

hooks = [
    types_models.MiddlewareHook.revalidateAuthentication.value,
    types_models.MiddlewareHook.mutatingPostAuthentication.value,
    types_models.MiddlewareHook.postAuthentication.value,
    types_models.MiddlewareHook.postLogout.value
]


def handler(module: types_request.register_module) -> Optional[Callable[[HttpRequest], HttpResponse]]:
    def wrapper(request: HttpRequest) -> HttpResponse:
        if request.method != "POST":
            return types_request.make_hook_error_response("Method %s Not Allowed".format(request.method))
        try:
            request_ctx = types_request.make_base_request_context(request)
            if request_ctx.user is None:
                return types_request.make_hook_error_response("User not found")
            output_data = module.func(request_ctx)
            return types_request.make_json_response(types_models.MiddlewareHookResponse(
                hook=types_models_ext.get_enum_by_value(types_models.MiddlewareHook, module.name),
                response=output_data.to_dict() if output_data else {},
                setClientRequestHeaders=request_ctx.clientRequest.headers
            ))
        except Exception as e:
            return types_request.make_hook_error_response(e)

    return wrapper
