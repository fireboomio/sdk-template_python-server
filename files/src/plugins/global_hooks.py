import json
from typing import Callable, Optional

from django.http import HttpRequest, HttpResponse

from custom_py.src.types import models as types_models, request as types_request
from custom_py.src.types import models_extension as types_models_ext
from custom_py.src.utils import json_parser

hooks = [
    types_models.MiddlewareHook.beforeOriginRequest.value,
    types_models.MiddlewareHook.afterOriginResponse.value,
]

global_hook_input_classes = {
    types_models.MiddlewareHook.beforeOriginRequest.value: types_models.OnRequestHookPayload,
    types_models.MiddlewareHook.afterOriginResponse.value: types_models.OnResponseHookPayload,
}


def handler(module: types_request.register_module) -> Optional[Callable[[HttpRequest], HttpResponse]]:
    input_class = global_hook_input_classes.get(module.name)
    if input_class is None:
        print(f"Module {module.name} Not Support")
        return None

    def wrapper(request: HttpRequest) -> HttpResponse:
        if request.method != "POST":
            return types_request.make_hook_error_response("Method %s Not Allowed".format(request.method))
        try:
            request_ctx = types_request.make_base_request_context(request)
            input_data = json_parser.parse_dict_to_class(json.loads(request.body), input_class)
            output_data = module.func(request_ctx, input_data)
            return types_request.make_json_response(types_models.MiddlewareHookResponse(
                op=input_data.operationName,
                hook=types_models_ext.get_enum_by_value(types_models.MiddlewareHook, module.name),
                response=output_data.to_dict() if output_data else {}
            ))
        except Exception as e:
            return types_request.make_hook_error_response(e)

    return wrapper
