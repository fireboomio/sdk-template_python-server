import json
from typing import Callable, Optional

from django.http import HttpRequest, HttpResponse, JsonResponse

from custom_py.src.types import models as types_models, request as types_request, models_extension as types_models_ext
from custom_py.src.utils import json_parser

hooks = [
    types_models.UploadHook.preUpload.value,
    types_models.UploadHook.postUpload.value
]


def handler(module: types_request.register_module) -> Optional[Callable[[HttpRequest], HttpResponse]]:
    upload_name = module.folder.removeprefix(types_models.HookParent.upload.value + "/").replace("/", "_")
    generated_models = types_models_ext.generated_models
    if generated_models is None:
        return None
    i_cls_name = upload_name + "ProfileMeta"
    if not hasattr(generated_models, i_cls_name):
        return None

    i_cls = getattr(generated_models, i_cls_name)

    def wrapper(request: HttpRequest) -> HttpResponse:
        if request.method != "POST":
            return types_request.make_hook_error_response("Method %s Not Allowed".format(request.method))
        try:
            request_ctx = types_request.make_base_request_context(request)
            input_data = json_parser.parse_dict_to_class(json.loads(request.body),
                                                         types_models_ext.UploadHookPayload)
            input_data.meta = json_parser.parse_dict_to_class(input_data.meta, i_cls)
            output_data = module.func(request_ctx, input_data)
            return types_request.make_json_response(output_data.to_json() if output_data else {})
        except Exception as e:
            return types_request.make_hook_error_response(e)

    return wrapper
