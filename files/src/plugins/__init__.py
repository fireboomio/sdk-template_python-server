from custom_py.src.plugins import authentication_hooks, global_hooks, operation_hooks, operation_functions, operation_proxys, upload_hooks
from custom_py.src.types import request as types_request, models as types_models

types_request.register_views(types_models.HookParent.authentication.value,
                             authentication_hooks.handler, authentication_hooks.hooks)
types_request.register_views(types_models.HookParent.global_.value, global_hooks.handler,
                             global_hooks.hooks, join_center='httpTransport')
types_request.register_views(types_models.HookParent.operation.value, operation_hooks.handler, operation_hooks.hooks)
types_request.register_views(types_models.HookParent.proxy.value, operation_proxys.handler)
types_request.register_views(types_models.HookParent.function.value, operation_functions.handler)
types_request.register_views(types_models.HookParent.upload.value, upload_hooks.handler, upload_hooks.hooks)
types_request.init_health_report_time()
