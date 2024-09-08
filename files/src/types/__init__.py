from custom_py.src.types import models as types_models, config as types_config

types_config.load_server_config()
types_models.register_init_parameter_renames()
