from custom_py.src.types import request as types_request, models as types_models


def beforeOriginRequest(ctx: types_request.request_context,
                        body: types_models.OnRequestHookPayload) -> types_models.WunderGraphRequest:
    return body.request
