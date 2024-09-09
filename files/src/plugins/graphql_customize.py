import json
import os
from typing import Callable, Optional

from django.http import HttpRequest, HttpResponseBase, StreamingHttpResponse
from django.shortcuts import render
from graphene import Schema

from custom_py.src.types import models as types_models, request as types_request
from custom_py.src.utils import json_parser, json_file


def handler(module: types_request.register_module) -> Optional[Callable[[HttpRequest], HttpResponseBase]]:
    if not isinstance(module.attr, Schema):
        return None
    graphql_path = os.path.join(module.folder, module.name)
    types_request.health_report.customizes.append(
        graphql_path.removeprefix(types_models.HookParent.customize.value + "/"))
    module.url = types_models.Endpoint.customize.value.replace("{name}", module.name)
    rewrite_graphql_json_file(graphql_path, module.attr)
    has_subscription = module.attr.subscription is not None

    def wrapper(request: HttpRequest) -> HttpResponseBase:
        if request.method == "GET":
            return render(request, 'graphql_helix.html', context={"graphqlEndpoint": module.url})

        try:
            input_data = json_parser.parse_dict_to_class(json.loads(request.body), types_models.CustomizeHookPayload)
            input_data_json = {
                "context_value": types_request.make_base_request_context(request),
                "variable_values": input_data.variables.to_json(),
                "operation_name": input_data.operationName
            }
            if has_subscription and input_data.query.startswith("subscription"):
                stream_data = module.attr.subscribe(query=input_data.query, **input_data_json)
                return StreamingHttpResponse(stream_data)

            normal_data = module.attr.execute(query=input_data.query, **input_data_json)
            return types_request.make_json_response(normal_data)
        except Exception as e:
            return types_request.make_hook_error_response(e)

    return wrapper


def rewrite_graphql_json_file(graphql_path: str, graphql_schema: Schema):
    introspect_str = ""
    graphql_json_path = graphql_path + ".json"
    try:
        introspect_str = json_file.read_file_as_text(graphql_json_path)
    except FileNotFoundError:
        pass
    introspect_data = graphql_schema.introspect()
    introspect_str_new = json_parser.json_dumps(introspect_data["__schema"])
    if sorted(introspect_str_new) == sorted(introspect_str):
        return
    json_file.write_text_to_file(introspect_str_new, graphql_json_path)
