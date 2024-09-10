from typing import IO

import requests

from custom_py.src.types import config as types_config
from custom_py.src.types import models as types_models
from custom_py.src.utils import json_parser


class upload_file:
    def __init__(self,
                 name: str,
                 file: IO):
        self.name = name
        self.file = file


class upload_parameter:
    def __init__(self,
                 files: list[upload_file],
                 directory: str = None,
                 profile: str = None,
                 keep_origin_name: bool = False,
                 headers: dict = None,
                 metadata: object = None):
        self.files = files
        self.directory = directory
        self.profile = profile
        self.keep_origin_name = keep_origin_name
        self.headers = headers
        self.metadata = metadata


class upload_client(types_models.S3UploadConfiguration):
    def get_internal_url(self) -> str:
        return (types_config.node_private_url
                + types_models.InternalEndpoint.s3upload.value.replace("{provider}", self.name))

    def upload(self, parameter: upload_parameter) -> types_models.UploadedFiles:
        files = [("file", (x.name, x.file)) for x in parameter.files]
        query_params = {}
        if parameter.directory:
            query_params["directory"] = parameter.directory
        if parameter.keep_origin_name:
            query_params["keepOriginName"] = parameter.keep_origin_name
        internal_url = self.get_internal_url()
        if len(query_params) > 0:
            internal_url += "?" + "&".join([f"{k}={v}" for k, v in query_params.items()])
        request_headers = {}
        if parameter.headers:
            request_headers = parameter.headers.copy()
        if parameter.profile:
            request_headers[types_models.InternalHeader.X_Upload_Profile.value] = parameter.profile
        if parameter.metadata:
            request_headers[types_models.InternalHeader.X_Metadata.value] = json_parser.json_dumps(parameter.metadata)
        response = requests.post(internal_url, files=files, headers=request_headers)
        if response.status_code != 200:
            raise Exception(response.reason)
        return json_parser.parse_list_to_class(response.json(), types_models.UploadedFiles)

    def get_oss_url(self, key: str) -> str:
        if not self.bucketName or not self.endpoint:
            for x in types_config.server_config.api.s3UploadConfiguration:
                if x.name == self.name:
                    self.useSSL = x.useSSL
                    self.bucketName = x.bucketName
                    self.endpoint = x.endpoint
                    break
        return "http{}://{}.{}/{}".format("s" if self.useSSL else "",
                                          types_config.get_configuration_val(self.bucketName),
                                          types_config.get_configuration_val(self.endpoint),
                                          key)
