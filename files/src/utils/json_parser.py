import json
from typing import TypeVar, Type, Union, Callable, Optional

from django.core.serializers.json import DjangoJSONEncoder


class init_parameter_rename:
    def __init__(self,
                 _from: str,
                 _to: str):
        self._from = _from
        self._to = _to

    def get_from(self):
        return self._from

    def get_to(self):
        return self._to


init_parameter_renames = {}

T = TypeVar('T')


def parse_dict_to_class(_dict: Union[dict, str, T], _cls: Type[T]) -> Optional[T]:
    if _dict is None:
        return None
    if isinstance(_dict, str):
        _dict = json.loads(_dict)
    return _cls(**rename_dict_keys(_dict, _cls)) if isinstance(_dict, dict) else _dict


def parse_list_to_class(_list: Union[list[Union[dict, T]], str], _cls: Type[T]) -> Optional[list[T]]:
    if _list is None:
        return None
    if isinstance(_list, str):
        _list = json.loads(_list)
    return [_cls(**rename_dict_keys(y, _cls)) if isinstance(y, dict) else y for y in _list]


def json_dumps(obj: object) -> str:
    if hasattr(obj, 'to_json'):
        obj = obj.to_json()
    if isinstance(obj, dict):
        obj = filter_null_keys(obj)
    return json.dumps(obj, default=filter_null_keys)


_json_encoder = DjangoJSONEncoder(default=lambda x: x)


def filter_null_keys(obj):
    if isinstance(obj, list):
        return [filter_null_keys(y) for y in obj]
    if isinstance(obj, dict):
        return {k: filter_null_keys(v) for k, v in obj.items() if v is not None}
    return _json_encoder.default(obj)


def rename_dict_keys(_dict: dict, _cls: Type[T]) -> dict:
    if not hasattr(_cls, "__origin__") and issubclass(_cls, dict):
        return _dict
    _dict = _rewrite_dict_keys(_dict, _cls, lambda x: x.get_from(), lambda x: x.get_to())
    cls_fields = get_class_fields(_cls)
    return {k: v for k, v in _dict.items() if k in cls_fields}


def get_class_fields(_cls: Type[T]) -> list[str]:
    return [attr for attr in dir(_cls()) if not hasattr(_cls, attr) and not attr.startswith("__")]


def recover_dict_keys(_dict: dict, _cls: Type[T]) -> dict:
    return _rewrite_dict_keys(_dict, _cls, lambda x: x.get_to(), lambda x: x.get_from())


def _rewrite_dict_keys(_dict: dict, _cls: Type[T],
                       _from_func: Callable[[init_parameter_rename], str],
                       _to_func: Callable[[init_parameter_rename], str]) -> dict:
    if _cls not in init_parameter_renames:
        return _dict
    for rename in init_parameter_renames[_cls]:
        _from = _from_func(rename)
        if _from not in _dict:
            continue
        _dict[_to_func(rename)] = _dict.pop(_from)
    return _dict
