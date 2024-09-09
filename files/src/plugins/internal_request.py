from typing import Generic, TypeVar

import requests

from custom_py.src.types import models as types_models, models_extension as types_models_ext
from custom_py.src.types import request as types_request, config as types_config
from custom_py.src.utils import json_parser

I = TypeVar("I")
O = TypeVar("O")


class internal_operation(Generic[I, O]):
    i_cls: type[I]
    o_cls: type[O]

    def __init__(self, path: str, operation_type: int):
        self.path = path
        self.operation_type = types_models_ext.get_enum_by_value(types_models.OperationType, operation_type)
        self.i_cls, self.o_cls = get_internal_operation_classes(path)

    def check_classes(self):
        if not self.i_cls or not self.o_cls:
            raise Exception("Invalid internal operation")

    def execute(self, input: I, client: types_request.internal_client) -> O:
        self.check_classes()
        internal_url = get_internal_request_url(self.path)
        client_request = types_models.WunderGraphRequest(
            headers=client.clientRequest.headers.to_json(),
            requestURI=internal_url,
            method="POST")
        base_body_wg = types_models.BaseRequestBodyWg(clientRequest=client_request, user=client.user)
        request_data = types_models.OperationHookPayload(input=input.to_json()).to_json()
        request_data['__wg'] = base_body_wg.to_json()
        request_headers = client.extraHeaders.to_json()
        request_headers["content-type"] = "application/json"
        response = requests.post(url=internal_url, data=json_parser.json_dumps(request_data), headers=request_headers)
        if response.status_code != 200:
            raise Exception(response.text)
        response_data = json_parser.parse_dict_to_class(response.json(), types_models.OperationHookPayload_response)
        if response_data.errors and len(response_data.errors) > 0:
            raise Exception(response_data.errors[0].message)
        return json_parser.parse_dict_to_class(response_data.data, self.o_cls)


def get_internal_request_url(path: str) -> str:
    return types_config.node_private_url + types_models.InternalEndpoint.internalRequest.value.replace("{path}", path)


def get_internal_operation_classes(path: str) -> (type, type):
    operation_name = path.replace("/", "__")
    generated_models = types_models_ext.generated_models
    if generated_models is None:
        return None
    i_cls_name = operation_name + "InternalInput"
    o_cls_name = operation_name + "ResponseData"
    if not hasattr(generated_models, i_cls_name) or not hasattr(generated_models, o_cls_name):
        return None

    i_cls = getattr(generated_models, i_cls_name)
    o_cls = getattr(generated_models, o_cls_name)
    return i_cls, o_cls
