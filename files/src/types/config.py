import os
from typing import Optional

from custom_py.src.types import models as types_models
from custom_py.src.utils import json_parser, json_file

server_config: types_models.WunderGraphConfiguration
node_public_url: str
node_private_url: str
server_listen_address: str
server_listen_port: str


def get_configuration_val(variable: types_models.ConfigurationVariable) -> Optional[str]:
    if variable is None:
        return None

    value = variable.staticVariableContent
    if variable.kind == types_models.ConfigurationVariableKind.ENV_CONFIGURATION_VARIABLE.value:
        value = os.getenv(variable.environmentVariableName)
        if value is None and variable.environmentVariableDefaultValue is not None:
            value = variable.environmentVariableDefaultValue
    return value


def load_server_config():
    global server_config, node_public_url, node_private_url, server_listen_address, server_listen_port
    _server_config_dict = json_file.read_file_as_dict("generated/fireboom.config.json")
    server_config = json_parser.parse_dict_to_class(_server_config_dict, types_models.WunderGraphConfiguration)
    _node_options = server_config.api.nodeOptions
    _server_listen = server_config.api.serverOptions.listen
    node_public_url = get_configuration_val(_node_options.publicNodeUrl)
    node_private_url = get_configuration_val(_node_options.nodeUrl)
    server_listen_address = get_configuration_val(_server_listen.host)
    server_listen_port = get_configuration_val(_server_listen.port)
