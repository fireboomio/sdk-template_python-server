from enum import Enum
from typing import TypeVar, Generic, Type, Optional

from custom_py.src.types import models as types_models
from custom_py.src.utils import json_parser, json_file

generated_models: None
I = TypeVar("I")
O = TypeVar("O")


class OperationHookPayload(Generic[I, O]):
    def __init__(self,
                 canceled: bool = None,
                 hook: types_models.MiddlewareHook = None,
                 input: I = None,
                 op: str = None,
                 response: 'OperationHookPayload_response[O]' = None,
                 setClientRequestHeaders: 'types_models.RequestHeaders' = None
                 ):
        self.canceled = canceled
        self.hook = hook
        self.input = input
        self.op = op
        self.response = json_parser.parse_dict_to_class(response, OperationHookPayload_response[O])
        self.setClientRequestHeaders = json_parser.parse_dict_to_class(setClientRequestHeaders,
                                                                       types_models.RequestHeaders)

    def to_json(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['hook'] = self.hook.value if self.hook else None
        _dict['input'] = self.input.to_json() \
            if hasattr(self.input, "to_json") else self.__dict__ \
            if self.input else None
        _dict['response'] = self.response.to_json() if self.response else None
        _dict['setClientRequestHeaders'] = self.setClientRequestHeaders.to_json() \
            if self.setClientRequestHeaders else None
        return {k: v for k, v in _dict.items() if not k.startswith('__')}


class OperationHookPayload_response(Generic[O]):
    def __init__(self,
                 data: O = None,
                 errors: list['types_models.RequestError'] = None
                 ):
        self.data = data
        self.errors = json_parser.parse_list_to_class(errors, types_models.RequestError)

    def to_json(self) -> dict:
        _dict = self.__dict__.copy()
        if isinstance(self.data, list):
            _dict['data'] = [x.to_json() if hasattr(x, "to_json") else x.__dict__ for x in self.data]
        elif not None:
            _dict['data'] = self.data.to_json() if hasattr(self.data, "to_json") else self.__dict__
        _dict['errors'] = [x.to_json() for x in self.errors] if self.errors else None
        return {k: v for k, v in _dict.items() if not k.startswith('__')}


class UploadHookPayload(Generic[I]):
    def __init__(self,
                 error: 'types_models.UploadHookPayload_error' = None,
                 file: 'types_models.HookFile' = None,
                 meta: I = None,
                 ):
        self.error = json_parser.parse_dict_to_class(error, types_models.UploadHookPayload_error)
        self.file = json_parser.parse_dict_to_class(file, types_models.HookFile)
        self.meta = meta

    def to_json(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['error'] = self.error.to_json() if self.error else None
        _dict['file'] = self.file.to_json() if self.file else None

        json_parser.recover_dict_keys(_dict, UploadHookPayload)
        return {k: v for k, v in _dict.items() if not k.startswith('__')}


def rewrite_operation_json_file(module_path: str, variables_schema: str = None, response_schema: str = None):
    operation = types_models.Operation()
    module_json_path = module_path + ".json"
    try:
        _dict = json_file.read_file_as_dict(module_json_path)
        operation = json_parser.parse_dict_to_class(_dict, types_models.Operation)
    except FileNotFoundError:
        pass

    if (operation.path == module_path
            and operation.variablesSchema == variables_schema
            and operation.responseSchema == response_schema):
        return
    operation.path = module_path
    operation.operationType = types_models.OperationType.MUTATION
    operation.variablesSchema = variables_schema
    operation.responseSchema = response_schema
    operation_str = json_parser.json_dumps(operation)
    json_file.write_text_to_file(operation_str, module_json_path)


def get_enum_by_value(enum_class: Type[Enum], value) -> Optional[Enum]:
    for member in enum_class.__members__.values():
        if member.value == value:
            return member
    return None
