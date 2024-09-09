import json
from typing import Callable, Optional

from django.http import HttpRequest, HttpResponse

from custom_py.src.plugins import internal_request
from custom_py.src.types import models as types_models, request as types_request, models_extension as types_models_ext
from custom_py.src.utils import json_parser

hooks = [
    types_models.MiddlewareHook.mutatingPreResolve.value,
    types_models.MiddlewareHook.preResolve.value,
    types_models.MiddlewareHook.mockResolve.value,
    types_models.MiddlewareHook.customResolve.value,
    types_models.MiddlewareHook.mutatingPostResolve.value,
    types_models.MiddlewareHook.postResolve.value
]


def handler(module: types_request.register_module) -> Optional[Callable[[HttpRequest], HttpResponse]]:
    operation_path = module.folder.removeprefix(types_models.HookParent.operation.value + "/")
    i_cls, o_cls = internal_request.get_internal_operation_classes(operation_path)
    if not i_cls or not o_cls:
        return None

    def wrapper(request: HttpRequest) -> HttpResponse:
        if request.method != "POST":
            return types_request.make_hook_error_response("Method %s Not Allowed".format(request.method))
        try:
            request_ctx = types_request.make_base_request_context(request)
            input_data = json_parser.parse_dict_to_class(json.loads(request.body),
                                                         types_models_ext.OperationHookPayload)
            input_data.input = json_parser.parse_dict_to_class(input_data.input, i_cls)
            if input_data.response is not None:
                input_data.response.data = json_parser.parse_dict_to_class(input_data.response.data, o_cls)
            input_data.op = operation_path
            input_data.hook = types_models_ext.get_enum_by_value(types_models.MiddlewareHook, module.name)
            output_data = module.func(request_ctx, input_data)
            if output_data is None:
                output_data = input_data
            return types_request.make_json_response(output_data.to_json())
        except Exception as e:
            return types_request.make_hook_error_response(e)

    return wrapper
