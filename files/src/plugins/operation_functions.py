import json
import os
from typing import Callable, Optional, Type

from django.http import HttpRequest, HttpResponse
from pydantic import BaseModel

from custom_py.src.types import models as types_models, request as types_request, models_extension as types_models_ext
from custom_py.src.utils import json_parser


def handler(module: types_request.register_module) -> Optional[Callable[[HttpRequest], HttpResponse]]:
    operation_path = os.path.join(module.folder, module.name)
    i_cls_name = module.name + "_input"
    o_cls_name = module.name + "_output"
    if not hasattr(module.import_, i_cls_name) or not hasattr(module.import_, o_cls_name):
        return None

    i_cls = getattr(module.import_, i_cls_name)
    o_cls = getattr(module.import_, o_cls_name)
    if not issubclass(i_cls, BaseModel) or not issubclass(o_cls, BaseModel):
        return None

    types_request.health_report.functions.append(
        operation_path.removeprefix(types_models.HookParent.function.value + "/"))
    types_models_ext.rewrite_operation_json_file(operation_path, get_json_schema_str(i_cls), get_json_schema_str(o_cls))

    def wrapper(request: HttpRequest) -> HttpResponse:
        if request.method != "POST":
            return types_request.make_hook_error_response("Method %s Not Allowed".format(request.method))
        try:
            request_ctx = types_request.make_base_request_context(request)
            input_data = json_parser.parse_dict_to_class(json.loads(request.body),
                                                         types_models_ext.OperationHookPayload)
            input_data.input = json_parser.parse_dict_to_class(input_data.input, i_cls)
            input_data.op = operation_path
            output_data = module.func(request_ctx, input_data)
            return types_request.make_json_response(output_data.to_dict() if output_data else {})
        except Exception as e:
            return types_request.make_hook_error_response(e)

    return wrapper


_json_schema_key_renames = {
    '"$defs"': '"definitions"',
    '"#/$defs/': '"#/definitions/'
}


def get_json_schema_str(_cls: Type[BaseModel]) -> str:
    json_schema_str = json_parser.json_dumps(_cls.schema())
    for k, v in _json_schema_key_renames.items():
        json_schema_str = json_schema_str.replace(k, v)
    return json_schema_str
