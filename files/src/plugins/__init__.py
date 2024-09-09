from custom_py.src.plugins import authentication_hooks, global_hooks, upload_hooks
from custom_py.src.plugins import graphql_customize
from custom_py.src.plugins import operation_functions, operation_proxys, operation_hooks
from custom_py.src.types import request as types_request, models as types_models

types_request.register_views(types_models.HookParent.authentication.value,
                             authentication_hooks.handler, authentication_hooks.hooks)
types_request.register_views(types_models.HookParent.global_.value, global_hooks.handler, global_hooks.hooks)
types_request.register_views(types_models.HookParent.operation.value, operation_hooks.handler, operation_hooks.hooks)
types_request.register_views(types_models.HookParent.proxy.value, operation_proxys.handler)
types_request.register_views(types_models.HookParent.function.value, operation_functions.handler)
types_request.register_views(types_models.HookParent.upload.value, upload_hooks.handler, upload_hooks.hooks)
types_request.register_views(types_models.HookParent.customize.value, graphql_customize.handler,
                             attr_name_suffix="_schema")
types_request.init_health_report_time()
