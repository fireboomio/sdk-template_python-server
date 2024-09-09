import json
import os
from typing import Callable, Optional

from django.http import HttpRequest, HttpResponse

from custom_py.src.types import models as types_models, request as types_request, models_extension as types_models_ext
from custom_py.src.utils import json_parser


def handler(module: types_request.register_module) -> Optional[Callable[[HttpRequest], HttpResponse]]:
    operation_path = os.path.join(module.folder, module.name)
    types_request.health_report.proxys.append(
        operation_path.removeprefix(types_models.HookParent.proxy.value + "/"))
    types_models_ext.rewrite_operation_json_file(operation_path)

    def wrapper(request: HttpRequest) -> HttpResponse:
        if request.method != "POST":
            return types_request.make_hook_error_response("Method {} Not Allowed".format(request.method))
        try:
            request_ctx = types_request.make_base_request_context(request)
            input_data = json_parser.parse_dict_to_class(json.loads(request.body), types_models.OnRequestHookPayload)
            output_data = module.func(request_ctx, input_data)
            return types_request.make_json_response(types_models.MiddlewareHookResponse(
                op=operation_path,
                response=output_data.to_json() if output_data else {}
            ))
        except Exception as e:
            return types_request.make_hook_error_response(e)

    return wrapper
