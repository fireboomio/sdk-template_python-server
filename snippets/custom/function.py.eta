from pydantic import BaseModel

from custom_py.src.types import request as types_request, models_extension as types_models_ext


class <%= it.name %>_data(BaseModel):
    age: int


class <%= it.name %>_map(BaseModel):
    pass


class <%= it.name %>_input(BaseModel):
    name: str


class <%= it.name %>_output(BaseModel):
    success: bool
    data: list[<%= it.name %>_data]
    map: <%= it.name %>_map


def <%= it.name %>(ctx: types_request.request_context,
         body: types_models_ext.OperationHookPayload[<%= it.name %>_input, <%= it.name %>_output]) \
        -> types_models_ext.OperationHookPayload[<%= it.name %>_input, <%= it.name %>_output]:
    pass
