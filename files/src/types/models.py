from enum import Enum
from typing import Optional
from custom_py.src.utils import json_parser
from datetime import datetime


class ArgumentRenderConfiguration(Enum):
    RENDER_ARGUMENT_DEFAULT = 0
    RENDER_ARGUMENT_AS_GRAPHQL_VALUE = 1
    RENDER_ARGUMENT_AS_ARRAY_CSV = 2
    RENDER_ARGUMENT_AS_JSON_VALUE = 3


class ArgumentSource(Enum):
    OBJECT_FIELD = 0
    FIELD_ARGUMENT = 1


class AuthProviderKind(Enum):
    AuthProviderGithub = 0
    AuthProviderOIDC = 1
    AuthProviderAuth0 = 2


class ClaimType(Enum):
    ISSUER = 0
    SUBJECT = 1
    WEBSITE = 10
    EMAIL = 11
    EMAIL_VERIFIED = 12
    GENDER = 13
    BIRTH_DATE = 14
    ZONE_INFO = 15
    LOCALE = 16
    LOCATION = 17
    ROLES = 18
    NAME = 2
    GIVEN_NAME = 3
    FAMILY_NAME = 4
    MIDDLE_NAME = 5
    NICKNAME = 6
    PREFERRED_USERNAME = 7
    PROFILE = 8
    PICTURE = 9
    CUSTOM = 999


class ConfigurationVariableKind(Enum):
    STATIC_CONFIGURATION_VARIABLE = 0
    ENV_CONFIGURATION_VARIABLE = 1
    PLACEHOLDER_CONFIGURATION_VARIABLE = 2


class CustomizeFlag(Enum):
    graphqlEndpoint = "${graphqlEndpoint}"
    __schema = "__schema"
    subscription = "subscription"


class DataSourceKind(Enum):
    STATIC = 0
    REST = 1
    GRAPHQL = 2
    POSTGRESQL = 3
    MYSQL = 4
    SQLSERVER = 5
    MONGODB = 6
    SQLITE = 7
    PRISMA = 8
    ASYNCAPI = 9


class DateOffsetUnit(Enum):
    YEAR = 0
    MONTH = 1
    DAY = 2
    HOUR = 3
    MINUTE = 4
    SECOND = 5


class Endpoint(Enum):
    mutatingPostAuthentication = "/authentication/mutatingPostAuthentication"
    postAuthentication = "/authentication/postAuthentication"
    postLogout = "/authentication/postLogout"
    revalidateAuthentication = "/authentication/revalidateAuthentication"
    function = "/function/{path}"
    afterOriginResponse = "/global/httpTransport/afterOriginResponse"
    beforeOriginRequest = "/global/httpTransport/beforeOriginRequest"
    onOriginRequest = "/global/httpTransport/onOriginRequest"
    onOriginResponse = "/global/httpTransport/onOriginResponse"
    onConnectionInit = "/global/wsTransport/onConnectionInit"
    customize = "/gqls/{name}/graphql"
    health = "/health"
    customResolve = "/operation/{path}/customResolve"
    mockResolve = "/operation/{path}/mockResolve"
    mutatingPostResolve = "/operation/{path}/mutatingPostResolve"
    mutatingPreResolve = "/operation/{path}/mutatingPreResolve"
    postResolve = "/operation/{path}/postResolve"
    preResolve = "/operation/{path}/preResolve"
    proxy = "/proxy/{path}"
    postUpload = "/upload/{provider}/{profile}/postUpload"
    preUpload = "/upload/{provider}/{profile}/preUpload"


class HTTPMethod(Enum):
    GET = 0
    POST = 1
    PUT = 2
    DELETE = 3
    OPTIONS = 4
    CONNECT = 5
    HEAD = 6
    PATCH = 7
    TRACE = 8


class HookParent(Enum):
    authentication = "authentication"
    customize = "customize"
    fragment = "fragment"
    function = "function"
    generated = "generated"
    global_ = "global"
    operation = "operation"
    proxy = "proxy"
    upload = "upload"


class InjectVariableKind(Enum):
    UUID = 0
    DATE_TIME = 1
    ENVIRONMENT_VARIABLE = 2
    FROM_HEADER = 3
    RULE_EXPRESSION = 4


class InternalEndpoint(Enum):
    internalTransaction = "/internal/notifyTransactionFinish"
    internalRequest = "/internal/operations/{path}"
    s3upload = "/s3/{provider}/upload"


class InternalHeader(Enum):
    X_Metadata = "X-Metadata"
    X_Request_Id = "X-Request-Id"
    X_Upload_Profile = "X-Upload-Profile"
    uber_trace_id = "uber-trace-id"


class MiddlewareHook(Enum):
    preResolve = "preResolve"
    mutatingPreResolve = "mutatingPreResolve"
    mockResolve = "mockResolve"
    customResolve = "customResolve"
    postResolve = "postResolve"
    mutatingPostResolve = "mutatingPostResolve"
    postAuthentication = "postAuthentication"
    mutatingPostAuthentication = "mutatingPostAuthentication"
    revalidateAuthentication = "revalidateAuthentication"
    postLogout = "postLogout"
    beforeOriginRequest = "beforeOriginRequest"
    afterOriginResponse = "afterOriginResponse"
    onOriginRequest = "onOriginRequest"
    onOriginResponse = "onOriginResponse"
    onConnectionInit = "onConnectionInit"


class OperationExecutionEngine(Enum):
    ENGINE_GRAPHQL = 0
    ENGINE_FUNCTION = 1
    ENGINE_PROXY = 2


class OperationField(Enum):
    operationType = "operationType"
    path = "path"
    responseSchema = "responseSchema"
    variablesSchema = "variablesSchema"


class OperationType(Enum):
    QUERY = 0
    MUTATION = 1
    SUBSCRIPTION = 2


class OperationTypeString(Enum):
    mutation = "mutation"
    query = "query"
    subscription = "subscription"


class PostResolveTransformationKind(Enum):
    GET_POST_RESOLVE_TRANSFORMATION = 0


class RateLimitHeader(Enum):
    x_rateLimit_perSecond = "x-rateLimit-perSecond"
    x_rateLimit_requests = "x-rateLimit-requests"
    x_rateLimit_uniqueKey = "x-rateLimit-uniqueKey"


class RbacHeader(Enum):
    x_rbac_denyMatchAll = "x-rbac-denyMatchAll"
    x_rbac_denyMatchAny = "x-rbac-denyMatchAny"
    x_rbac_requireMatchAll = "x-rbac-requireMatchAll"
    x_rbac_requireMatchAny = "x-rbac-requireMatchAny"


class SigningMethod(Enum):
    SigningMethodHS256 = 0


class TransactionHeader(Enum):
    X_Transaction_Id = "X-Transaction-Id"
    X_Transaction_Manually = "X-Transaction-Manually"


class UploadHook(Enum):
    preUpload = "preUpload"
    postUpload = "postUpload"


class UpstreamAuthenticationKind(Enum):
    UpstreamAuthenticationJWT = 0
    UpstreamAuthenticationJWTWithAccessTokenExchange = 1


class ValueType(Enum):
    STRING = 0
    INT = 1
    FLOAT = 2
    BOOLEAN = 3
    ARRAY = 4


class VariableWhereInputRelationFilterType(Enum):
    is_ = 0
    isNot = 1
    some = 2
    every = 3
    none = 4


class VariableWhereInputScalarFilterType(Enum):
    equals = 0
    in_ = 1
    notIn = 2
    lt = 3
    lte = 4
    gt = 5
    gte = 6
    contains = 7
    startsWith = 8
    endsWith = 9


class WebhookVerifierKind(Enum):
    HMAC_SHA256 = 0


class ApiAuthenticationConfig:
    def __init__(self,
                 cookieBased: 'CookieBasedAuthentication' = None,
                 hooks: 'ApiAuthenticationHooks' = None,
                 jwksBased: 'JwksBasedAuthentication' = None,
                 publicClaims: list[str] = None
                 ):
        self.cookieBased = json_parser.parse_dict_to_class(cookieBased, CookieBasedAuthentication)
        self.hooks = json_parser.parse_dict_to_class(hooks, ApiAuthenticationHooks)
        self.jwksBased = json_parser.parse_dict_to_class(jwksBased, JwksBasedAuthentication)
        self.publicClaims = publicClaims

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['cookieBased'] = self.cookieBased.to_json() if self.cookieBased else None
        _json['hooks'] = self.hooks.to_json() if self.hooks else None
        _json['jwksBased'] = self.jwksBased.to_json() if self.jwksBased else None
        json_parser.recover_dict_keys(_json, ApiAuthenticationConfig)
        return _json


class ApiAuthenticationHooks:
    def __init__(self,
                 mutatingPostAuthentication: bool = None,
                 postAuthentication: bool = None,
                 postLogout: bool = None,
                 revalidateAuthentication: bool = None
                 ):
        self.mutatingPostAuthentication = mutatingPostAuthentication
        self.postAuthentication = postAuthentication
        self.postLogout = postLogout
        self.revalidateAuthentication = revalidateAuthentication

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, ApiAuthenticationHooks)
        return _json


class ArgumentConfiguration:
    def __init__(self,
                 name: str = None,
                 renameTypeTo: str = None,
                 renderConfiguration: ArgumentRenderConfiguration = None,
                 sourcePath: list[str] = None,
                 sourceType: ArgumentSource = None
                 ):
        self.name = name
        self.renameTypeTo = renameTypeTo
        self.renderConfiguration = renderConfiguration
        self.sourcePath = sourcePath
        self.sourceType = sourceType

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['renderConfiguration'] = self.renderConfiguration.value if self.renderConfiguration else None
        _json['sourceType'] = self.sourceType.value if self.sourceType else None
        json_parser.recover_dict_keys(_json, ArgumentConfiguration)
        return _json


class AuthProvider:
    def __init__(self,
                 githubConfig: 'GithubAuthProviderConfig' = None,
                 id: str = None,
                 kind: AuthProviderKind = None,
                 oidcConfig: 'OpenIDConnectAuthProviderConfig' = None
                 ):
        self.githubConfig = json_parser.parse_dict_to_class(githubConfig, GithubAuthProviderConfig)
        self.id = id
        self.kind = kind
        self.oidcConfig = json_parser.parse_dict_to_class(oidcConfig, OpenIDConnectAuthProviderConfig)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['githubConfig'] = self.githubConfig.to_json() if self.githubConfig else None
        _json['kind'] = self.kind.value if self.kind else None
        _json['oidcConfig'] = self.oidcConfig.to_json() if self.oidcConfig else None
        json_parser.recover_dict_keys(_json, AuthProvider)
        return _json


class BaseRequestBody:
    def __init__(self,
                 __wg: Optional['BaseRequestBodyWg'] = None
                 ):
        self.__wg = json_parser.parse_dict_to_class(__wg, BaseRequestBodyWg)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['__wg'] = self.__wg.to_json() if self.__wg else None
        json_parser.recover_dict_keys(_json, BaseRequestBody)
        return _json


class BaseRequestBodyWg:
    def __init__(self,
                 clientRequest: 'WunderGraphRequest' = None,
                 user: 'User' = None
                 ):
        self.clientRequest = json_parser.parse_dict_to_class(clientRequest, WunderGraphRequest)
        self.user = json_parser.parse_dict_to_class(user, User)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['clientRequest'] = self.clientRequest.to_json() if self.clientRequest else None
        _json['user'] = self.user.to_json() if self.user else None
        json_parser.recover_dict_keys(_json, BaseRequestBodyWg)
        return _json


class ClaimConfig:
    def __init__(self,
                 claimType: ClaimType = None,
                 custom: 'CustomClaim' = None,
                 variablePathComponents: list[str] = None
                 ):
        self.claimType = claimType
        self.custom = json_parser.parse_dict_to_class(custom, CustomClaim)
        self.variablePathComponents = variablePathComponents

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['claimType'] = self.claimType.value if self.claimType else None
        _json['custom'] = self.custom.to_json() if self.custom else None
        json_parser.recover_dict_keys(_json, ClaimConfig)
        return _json


class ConfigurationVariable:
    def __init__(self,
                 kind: ConfigurationVariableKind = None,
                 environmentVariableDefaultValue: Optional[str] = None,
                 environmentVariableName: Optional[str] = None,
                 placeholderVariableName: Optional[str] = None,
                 staticVariableContent: Optional[str] = None
                 ):
        self.kind = kind
        self.environmentVariableDefaultValue = environmentVariableDefaultValue
        self.environmentVariableName = environmentVariableName
        self.placeholderVariableName = placeholderVariableName
        self.staticVariableContent = staticVariableContent

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['kind'] = self.kind.value if self.kind else None
        json_parser.recover_dict_keys(_json, ConfigurationVariable)
        return _json


class CookieBasedAuthentication:
    def __init__(self,
                 authorizedRedirectUriRegexes: list['ConfigurationVariable'] = None,
                 authorizedRedirectUris: list['ConfigurationVariable'] = None,
                 blockKey: 'ConfigurationVariable' = None,
                 csrfSecret: 'ConfigurationVariable' = None,
                 hashKey: 'ConfigurationVariable' = None,
                 providers: list['AuthProvider'] = None
                 ):
        self.authorizedRedirectUriRegexes = json_parser.parse_list_to_class(authorizedRedirectUriRegexes,
                                                                            ConfigurationVariable)
        self.authorizedRedirectUris = json_parser.parse_list_to_class(authorizedRedirectUris, ConfigurationVariable)
        self.blockKey = json_parser.parse_dict_to_class(blockKey, ConfigurationVariable)
        self.csrfSecret = json_parser.parse_dict_to_class(csrfSecret, ConfigurationVariable)
        self.hashKey = json_parser.parse_dict_to_class(hashKey, ConfigurationVariable)
        self.providers = json_parser.parse_list_to_class(providers, AuthProvider)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['authorizedRedirectUriRegexes'] = [x.to_json() for x in
                                                 self.authorizedRedirectUriRegexes] if self.authorizedRedirectUriRegexes else None
        _json['authorizedRedirectUris'] = [x.to_json() for x in
                                           self.authorizedRedirectUris] if self.authorizedRedirectUris else None
        _json['blockKey'] = self.blockKey.to_json() if self.blockKey else None
        _json['csrfSecret'] = self.csrfSecret.to_json() if self.csrfSecret else None
        _json['hashKey'] = self.hashKey.to_json() if self.hashKey else None
        _json['providers'] = [x.to_json() for x in self.providers] if self.providers else None
        json_parser.recover_dict_keys(_json, CookieBasedAuthentication)
        return _json


class CorsConfiguration:
    def __init__(self,
                 allowCredentials: bool = None,
                 allowedHeaders: list[str] = None,
                 allowedMethods: list[str] = None,
                 allowedOrigins: list['ConfigurationVariable'] = None,
                 exposedHeaders: list[str] = None,
                 maxAge: int = None
                 ):
        self.allowCredentials = allowCredentials
        self.allowedHeaders = allowedHeaders
        self.allowedMethods = allowedMethods
        self.allowedOrigins = json_parser.parse_list_to_class(allowedOrigins, ConfigurationVariable)
        self.exposedHeaders = exposedHeaders
        self.maxAge = maxAge

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['allowedOrigins'] = [x.to_json() for x in self.allowedOrigins] if self.allowedOrigins else None
        json_parser.recover_dict_keys(_json, CorsConfiguration)
        return _json


class CustomClaim:
    def __init__(self,
                 jsonPathComponents: list[str] = None,
                 name: str = None,
                 required: bool = None,
                 type: ValueType = None
                 ):
        self.jsonPathComponents = jsonPathComponents
        self.name = name
        self.required = required
        self.type = type

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['type'] = self.type.value if self.type else None
        json_parser.recover_dict_keys(_json, CustomClaim)
        return _json


class CustomizeHookPayload:
    def __init__(self,
                 operationName: str = None,
                 query: str = None,
                 variables: 'CustomizeHookPayload_variables' = None,
                 __wg: Optional['BaseRequestBodyWg'] = None
                 ):
        self.operationName = operationName
        self.query = query
        self.variables = json_parser.parse_dict_to_class(variables, CustomizeHookPayload_variables)
        self.__wg = json_parser.parse_dict_to_class(__wg, BaseRequestBodyWg)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['variables'] = self.variables.to_json() if self.variables else None
        _json['__wg'] = self.__wg.to_json() if self.__wg else None
        json_parser.recover_dict_keys(_json, CustomizeHookPayload)
        return _json


class CustomizeHookPayload_variables(dict[str, object]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        return _json


class CustomizeHookResponse:
    def __init__(self,
                 data: object = None,
                 errors: list['RequestError'] = None,
                 extensions: 'CustomizeHookResponse_extensions' = None
                 ):
        self.data = data
        self.errors = json_parser.parse_list_to_class(errors, RequestError)
        self.extensions = json_parser.parse_dict_to_class(extensions, CustomizeHookResponse_extensions)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['errors'] = [x.to_json() for x in self.errors] if self.errors else None
        _json['extensions'] = self.extensions.to_json() if self.extensions else None
        json_parser.recover_dict_keys(_json, CustomizeHookResponse)
        return _json


class CustomizeHookResponse_extensions(dict[str, object]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        return _json


class DataSourceConfiguration:
    def __init__(self,
                 childNodes: list['TypeField'] = None,
                 customDatabase: 'DataSourceCustom_Database' = None,
                 customGraphql: 'DataSourceCustom_GraphQL' = None,
                 customRest: 'DataSourceCustom_REST' = None,
                 customStatic: 'DataSourceCustom_Static' = None,
                 directives: list['DirectiveConfiguration'] = None,
                 id: str = None,
                 kind: DataSourceKind = None,
                 overrideFieldPathFromAlias: bool = None,
                 requestTimeoutSeconds: int = None,
                 rootNodes: list['TypeField'] = None,
                 customRestMap: Optional['DataSourceConfiguration_customRestMap'] = None,
                 customRestRequestRewriterMap: Optional['DataSourceConfiguration_customRestRequestRewriterMap'] = None,
                 customRestResponseRewriterMap: Optional[
                     'DataSourceConfiguration_customRestResponseRewriterMap'] = None,
                 kindForPrisma: Optional[int] = None
                 ):
        self.childNodes = json_parser.parse_list_to_class(childNodes, TypeField)
        self.customDatabase = json_parser.parse_dict_to_class(customDatabase, DataSourceCustom_Database)
        self.customGraphql = json_parser.parse_dict_to_class(customGraphql, DataSourceCustom_GraphQL)
        self.customRest = json_parser.parse_dict_to_class(customRest, DataSourceCustom_REST)
        self.customStatic = json_parser.parse_dict_to_class(customStatic, DataSourceCustom_Static)
        self.directives = json_parser.parse_list_to_class(directives, DirectiveConfiguration)
        self.id = id
        self.kind = kind
        self.overrideFieldPathFromAlias = overrideFieldPathFromAlias
        self.requestTimeoutSeconds = requestTimeoutSeconds
        self.rootNodes = json_parser.parse_list_to_class(rootNodes, TypeField)
        self.customRestMap = json_parser.parse_dict_to_class(customRestMap, DataSourceConfiguration_customRestMap)
        self.customRestRequestRewriterMap = json_parser.parse_dict_to_class(customRestRequestRewriterMap,
                                                                            DataSourceConfiguration_customRestRequestRewriterMap)
        self.customRestResponseRewriterMap = json_parser.parse_dict_to_class(customRestResponseRewriterMap,
                                                                             DataSourceConfiguration_customRestResponseRewriterMap)
        self.kindForPrisma = kindForPrisma

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['childNodes'] = [x.to_json() for x in self.childNodes] if self.childNodes else None
        _json['customDatabase'] = self.customDatabase.to_json() if self.customDatabase else None
        _json['customGraphql'] = self.customGraphql.to_json() if self.customGraphql else None
        _json['customRest'] = self.customRest.to_json() if self.customRest else None
        _json['customStatic'] = self.customStatic.to_json() if self.customStatic else None
        _json['directives'] = [x.to_json() for x in self.directives] if self.directives else None
        _json['kind'] = self.kind.value if self.kind else None
        _json['rootNodes'] = [x.to_json() for x in self.rootNodes] if self.rootNodes else None
        _json['customRestMap'] = self.customRestMap.to_json() if self.customRestMap else None
        _json[
            'customRestRequestRewriterMap'] = self.customRestRequestRewriterMap.to_json() if self.customRestRequestRewriterMap else None
        _json[
            'customRestResponseRewriterMap'] = self.customRestResponseRewriterMap.to_json() if self.customRestResponseRewriterMap else None
        json_parser.recover_dict_keys(_json, DataSourceConfiguration)
        return _json


class DataSourceConfiguration_customRestMap(dict[str, 'DataSourceCustom_REST']):
    def __init__(self, *args, **kwargs):
        args = tuple([{k: json_parser.parse_dict_to_class(v, DataSourceCustom_REST) for k, v in arg} for arg in args])
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        _json = {k: json_parser.recover_dict_keys(v.to_json(), DataSourceCustom_REST) for k, v in _json.items()}
        return _json


class DataSourceConfiguration_customRestRequestRewriterMap(dict[str, 'DataSourceCustom_REST_Rewriter']):
    def __init__(self, *args, **kwargs):
        args = tuple(
            [{k: json_parser.parse_dict_to_class(v, DataSourceCustom_REST_Rewriter) for k, v in arg} for arg in args])
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        _json = {k: json_parser.recover_dict_keys(v.to_json(), DataSourceCustom_REST_Rewriter) for k, v in
                 _json.items()}
        return _json


class DataSourceConfiguration_customRestResponseRewriterMap(dict[str, 'DataSourceCustom_REST_Rewriter']):
    def __init__(self, *args, **kwargs):
        args = tuple(
            [{k: json_parser.parse_dict_to_class(v, DataSourceCustom_REST_Rewriter) for k, v in arg} for arg in args])
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        _json = {k: json_parser.recover_dict_keys(v.to_json(), DataSourceCustom_REST_Rewriter) for k, v in
                 _json.items()}
        return _json


class DataSourceCustom_Database:
    def __init__(self,
                 closeTimeoutSeconds: int = None,
                 databaseURL: 'ConfigurationVariable' = None,
                 environmentVariable: str = None,
                 graphqlSchema: str = None,
                 jsonInputVariables: list[str] = None,
                 jsonTypeFields: list['SingleTypeField'] = None,
                 prismaSchema: str = None
                 ):
        self.closeTimeoutSeconds = closeTimeoutSeconds
        self.databaseURL = json_parser.parse_dict_to_class(databaseURL, ConfigurationVariable)
        self.environmentVariable = environmentVariable
        self.graphqlSchema = graphqlSchema
        self.jsonInputVariables = jsonInputVariables
        self.jsonTypeFields = json_parser.parse_list_to_class(jsonTypeFields, SingleTypeField)
        self.prismaSchema = prismaSchema

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['databaseURL'] = self.databaseURL.to_json() if self.databaseURL else None
        _json['jsonTypeFields'] = [x.to_json() for x in self.jsonTypeFields] if self.jsonTypeFields else None
        json_parser.recover_dict_keys(_json, DataSourceCustom_Database)
        return _json


class DataSourceCustom_GraphQL:
    def __init__(self,
                 customScalarTypeFields: list['SingleTypeField'] = None,
                 federation: 'GraphQLFederationConfiguration' = None,
                 fetch: 'FetchConfiguration' = None,
                 hooksConfiguration: 'GraphQLDataSourceHooksConfiguration' = None,
                 subscription: 'GraphQLSubscriptionConfiguration' = None,
                 upstreamSchema: str = None
                 ):
        self.customScalarTypeFields = json_parser.parse_list_to_class(customScalarTypeFields, SingleTypeField)
        self.federation = json_parser.parse_dict_to_class(federation, GraphQLFederationConfiguration)
        self.fetch = json_parser.parse_dict_to_class(fetch, FetchConfiguration)
        self.hooksConfiguration = json_parser.parse_dict_to_class(hooksConfiguration,
                                                                  GraphQLDataSourceHooksConfiguration)
        self.subscription = json_parser.parse_dict_to_class(subscription, GraphQLSubscriptionConfiguration)
        self.upstreamSchema = upstreamSchema

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['customScalarTypeFields'] = [x.to_json() for x in
                                           self.customScalarTypeFields] if self.customScalarTypeFields else None
        _json['federation'] = self.federation.to_json() if self.federation else None
        _json['fetch'] = self.fetch.to_json() if self.fetch else None
        _json['hooksConfiguration'] = self.hooksConfiguration.to_json() if self.hooksConfiguration else None
        _json['subscription'] = self.subscription.to_json() if self.subscription else None
        json_parser.recover_dict_keys(_json, DataSourceCustom_GraphQL)
        return _json


class DataSourceCustom_REST:
    def __init__(self,
                 defaultTypeName: str = None,
                 fetch: 'FetchConfiguration' = None,
                 statusCodeTypeMappings: list['StatusCodeTypeMapping'] = None,
                 subscription: 'RESTSubscriptionConfiguration' = None,
                 requestRewriters: Optional[list['DataSourceRESTRewriter']] = None,
                 responseExtractor: Optional['DataSourceRESTResponseExtractor'] = None,
                 responseRewriters: Optional[list['DataSourceRESTRewriter']] = None
                 ):
        self.defaultTypeName = defaultTypeName
        self.fetch = json_parser.parse_dict_to_class(fetch, FetchConfiguration)
        self.statusCodeTypeMappings = json_parser.parse_list_to_class(statusCodeTypeMappings, StatusCodeTypeMapping)
        self.subscription = json_parser.parse_dict_to_class(subscription, RESTSubscriptionConfiguration)
        self.requestRewriters = json_parser.parse_list_to_class(requestRewriters, DataSourceRESTRewriter)
        self.responseExtractor = json_parser.parse_dict_to_class(responseExtractor, DataSourceRESTResponseExtractor)
        self.responseRewriters = json_parser.parse_list_to_class(responseRewriters, DataSourceRESTRewriter)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['fetch'] = self.fetch.to_json() if self.fetch else None
        _json['statusCodeTypeMappings'] = [x.to_json() for x in
                                           self.statusCodeTypeMappings] if self.statusCodeTypeMappings else None
        _json['subscription'] = self.subscription.to_json() if self.subscription else None
        _json['requestRewriters'] = [x.to_json() for x in self.requestRewriters] if self.requestRewriters else None
        _json['responseExtractor'] = self.responseExtractor.to_json() if self.responseExtractor else None
        _json['responseRewriters'] = [x.to_json() for x in self.responseRewriters] if self.responseRewriters else None
        json_parser.recover_dict_keys(_json, DataSourceCustom_REST)
        return _json


class DataSourceCustom_REST_Rewriter:
    def __init__(self,
                 rewriters: list['DataSourceRESTRewriter'] = None
                 ):
        self.rewriters = json_parser.parse_list_to_class(rewriters, DataSourceRESTRewriter)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['rewriters'] = [x.to_json() for x in self.rewriters] if self.rewriters else None
        json_parser.recover_dict_keys(_json, DataSourceCustom_REST_Rewriter)
        return _json


class DataSourceCustom_Static:
    def __init__(self,
                 data: 'ConfigurationVariable' = None
                 ):
        self.data = json_parser.parse_dict_to_class(data, ConfigurationVariable)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['data'] = self.data.to_json() if self.data else None
        json_parser.recover_dict_keys(_json, DataSourceCustom_Static)
        return _json


class DataSourceRESTResponseExtractor:
    def __init__(self,
                 errorMessageJsonpath: str = None,
                 statusCodeJsonpath: str = None,
                 statusCodeScopes: list['DataSourceRESTResponseStatusCodeScope'] = None
                 ):
        self.errorMessageJsonpath = errorMessageJsonpath
        self.statusCodeJsonpath = statusCodeJsonpath
        self.statusCodeScopes = json_parser.parse_list_to_class(statusCodeScopes, DataSourceRESTResponseStatusCodeScope)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['statusCodeScopes'] = [x.to_json() for x in self.statusCodeScopes] if self.statusCodeScopes else None
        json_parser.recover_dict_keys(_json, DataSourceRESTResponseExtractor)
        return _json


class DataSourceRESTResponseStatusCodeScope:
    def __init__(self,
                 max: int = None,
                 min: int = None
                 ):
        self.max = max
        self.min = min

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, DataSourceRESTResponseStatusCodeScope)
        return _json


class DataSourceRESTRewriter:
    def __init__(self,
                 pathComponents: list[str] = None,
                 type: int = None,
                 applySubCommonField: Optional[str] = None,
                 applySubCommonFieldValues: Optional['DataSourceRESTRewriter_applySubCommonFieldValues'] = None,
                 applySubFieldTypes: Optional[list['DataSourceRESTSubfield']] = None,
                 applySubObjects: Optional[list['DataSourceRESTSubObject']] = None,
                 customEnumField: Optional[str] = None,
                 customObjectName: Optional[str] = None,
                 fieldRewriteTo: Optional[str] = None,
                 quoteObjectName: Optional[str] = None,
                 valueRewrites: Optional['DataSourceRESTRewriter_valueRewrites'] = None
                 ):
        self.pathComponents = pathComponents
        self.type = type
        self.applySubCommonField = applySubCommonField
        self.applySubCommonFieldValues = json_parser.parse_dict_to_class(applySubCommonFieldValues,
                                                                         DataSourceRESTRewriter_applySubCommonFieldValues)
        self.applySubFieldTypes = json_parser.parse_list_to_class(applySubFieldTypes, DataSourceRESTSubfield)
        self.applySubObjects = json_parser.parse_list_to_class(applySubObjects, DataSourceRESTSubObject)
        self.customEnumField = customEnumField
        self.customObjectName = customObjectName
        self.fieldRewriteTo = fieldRewriteTo
        self.quoteObjectName = quoteObjectName
        self.valueRewrites = json_parser.parse_dict_to_class(valueRewrites, DataSourceRESTRewriter_valueRewrites)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json[
            'applySubCommonFieldValues'] = self.applySubCommonFieldValues.to_json() if self.applySubCommonFieldValues else None
        _json['applySubFieldTypes'] = [x.to_json() for x in
                                       self.applySubFieldTypes] if self.applySubFieldTypes else None
        _json['applySubObjects'] = [x.to_json() for x in self.applySubObjects] if self.applySubObjects else None
        _json['valueRewrites'] = self.valueRewrites.to_json() if self.valueRewrites else None
        json_parser.recover_dict_keys(_json, DataSourceRESTRewriter)
        return _json


class DataSourceRESTRewriter_applySubCommonFieldValues(dict[str, str]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        return _json


class DataSourceRESTRewriter_valueRewrites(dict[str, str]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        return _json


class DataSourceRESTSubObject:
    def __init__(self,
                 fields: list['DataSourceRESTSubfield'] = None,
                 name: str = None
                 ):
        self.fields = json_parser.parse_list_to_class(fields, DataSourceRESTSubfield)
        self.name = name

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['fields'] = [x.to_json() for x in self.fields] if self.fields else None
        json_parser.recover_dict_keys(_json, DataSourceRESTSubObject)
        return _json


class DataSourceRESTSubfield:
    def __init__(self,
                 name: str = None,
                 type: int = None
                 ):
        self.name = name
        self.type = type

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, DataSourceRESTSubfield)
        return _json


class DatasourceQuote:
    def __init__(self,
                 fields: list[str] = None
                 ):
        self.fields = fields

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, DatasourceQuote)
        return _json


class DateOffset:
    def __init__(self,
                 previous: bool = None,
                 unit: DateOffsetUnit = None,
                 value: int = None,
                 format: Optional[str] = None
                 ):
        self.previous = previous
        self.unit = unit
        self.value = value
        self.format = format

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['unit'] = self.unit.value if self.unit else None
        json_parser.recover_dict_keys(_json, DateOffset)
        return _json


class DirectiveConfiguration:
    def __init__(self,
                 directiveName: str = None,
                 renameTo: str = None
                 ):
        self.directiveName = directiveName
        self.renameTo = renameTo

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, DirectiveConfiguration)
        return _json


class EngineConfiguration:
    def __init__(self,
                 datasourceConfigurations: list['DataSourceConfiguration'] = None,
                 defaultFlushInterval: int = None,
                 fieldConfigurations: list['FieldConfiguration'] = None,
                 graphqlSchema: str = None,
                 typeConfigurations: list['TypeConfiguration'] = None
                 ):
        self.datasourceConfigurations = json_parser.parse_list_to_class(datasourceConfigurations,
                                                                        DataSourceConfiguration)
        self.defaultFlushInterval = defaultFlushInterval
        self.fieldConfigurations = json_parser.parse_list_to_class(fieldConfigurations, FieldConfiguration)
        self.graphqlSchema = graphqlSchema
        self.typeConfigurations = json_parser.parse_list_to_class(typeConfigurations, TypeConfiguration)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['datasourceConfigurations'] = [x.to_json() for x in
                                             self.datasourceConfigurations] if self.datasourceConfigurations else None
        _json['fieldConfigurations'] = [x.to_json() for x in
                                        self.fieldConfigurations] if self.fieldConfigurations else None
        _json['typeConfigurations'] = [x.to_json() for x in
                                       self.typeConfigurations] if self.typeConfigurations else None
        json_parser.recover_dict_keys(_json, EngineConfiguration)
        return _json


class ErrorPath:
    def __init__(self):
        pass

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, ErrorPath)
        return _json


class FetchConfiguration:
    def __init__(self,
                 baseUrl: 'ConfigurationVariable' = None,
                 body: 'ConfigurationVariable' = None,
                 header: 'FetchConfiguration_header' = None,
                 mTLS: 'MTLSConfiguration' = None,
                 method: HTTPMethod = None,
                 path: 'ConfigurationVariable' = None,
                 query: list['URLQueryConfiguration'] = None,
                 requestContentType: str = None,
                 responseContentType: str = None,
                 upstreamAuthentication: 'UpstreamAuthentication' = None,
                 url: 'ConfigurationVariable' = None,
                 urlEncodeBody: bool = None
                 ):
        self.baseUrl = json_parser.parse_dict_to_class(baseUrl, ConfigurationVariable)
        self.body = json_parser.parse_dict_to_class(body, ConfigurationVariable)
        self.header = json_parser.parse_dict_to_class(header, FetchConfiguration_header)
        self.mTLS = json_parser.parse_dict_to_class(mTLS, MTLSConfiguration)
        self.method = method
        self.path = json_parser.parse_dict_to_class(path, ConfigurationVariable)
        self.query = json_parser.parse_list_to_class(query, URLQueryConfiguration)
        self.requestContentType = requestContentType
        self.responseContentType = responseContentType
        self.upstreamAuthentication = json_parser.parse_dict_to_class(upstreamAuthentication, UpstreamAuthentication)
        self.url = json_parser.parse_dict_to_class(url, ConfigurationVariable)
        self.urlEncodeBody = urlEncodeBody

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['baseUrl'] = self.baseUrl.to_json() if self.baseUrl else None
        _json['body'] = self.body.to_json() if self.body else None
        _json['header'] = self.header.to_json() if self.header else None
        _json['mTLS'] = self.mTLS.to_json() if self.mTLS else None
        _json['method'] = self.method.value if self.method else None
        _json['path'] = self.path.to_json() if self.path else None
        _json['query'] = [x.to_json() for x in self.query] if self.query else None
        _json['upstreamAuthentication'] = self.upstreamAuthentication.to_json() if self.upstreamAuthentication else None
        _json['url'] = self.url.to_json() if self.url else None
        json_parser.recover_dict_keys(_json, FetchConfiguration)
        return _json


class FetchConfiguration_header(dict[str, 'HTTPHeader']):
    def __init__(self, *args, **kwargs):
        args = tuple([{k: json_parser.parse_dict_to_class(v, HTTPHeader) for k, v in arg} for arg in args])
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        _json = {k: json_parser.recover_dict_keys(v.to_json(), HTTPHeader) for k, v in _json.items()}
        return _json


class FieldConfiguration:
    def __init__(self,
                 argumentsConfiguration: list['ArgumentConfiguration'] = None,
                 disableDefaultFieldMapping: bool = None,
                 fieldName: str = None,
                 path: list[str] = None,
                 requiresFields: list[str] = None,
                 typeName: str = None,
                 unescapeResponseJson: bool = None
                 ):
        self.argumentsConfiguration = json_parser.parse_list_to_class(argumentsConfiguration, ArgumentConfiguration)
        self.disableDefaultFieldMapping = disableDefaultFieldMapping
        self.fieldName = fieldName
        self.path = path
        self.requiresFields = requiresFields
        self.typeName = typeName
        self.unescapeResponseJson = unescapeResponseJson

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['argumentsConfiguration'] = [x.to_json() for x in
                                           self.argumentsConfiguration] if self.argumentsConfiguration else None
        json_parser.recover_dict_keys(_json, FieldConfiguration)
        return _json


class GithubAuthProviderConfig:
    def __init__(self,
                 clientId: 'ConfigurationVariable' = None,
                 clientSecret: 'ConfigurationVariable' = None
                 ):
        self.clientId = json_parser.parse_dict_to_class(clientId, ConfigurationVariable)
        self.clientSecret = json_parser.parse_dict_to_class(clientSecret, ConfigurationVariable)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['clientId'] = self.clientId.to_json() if self.clientId else None
        _json['clientSecret'] = self.clientSecret.to_json() if self.clientSecret else None
        json_parser.recover_dict_keys(_json, GithubAuthProviderConfig)
        return _json


class GraphQLDataSourceHooksConfiguration:
    def __init__(self,
                 onWSTransportConnectionInit: bool = None
                 ):
        self.onWSTransportConnectionInit = onWSTransportConnectionInit

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, GraphQLDataSourceHooksConfiguration)
        return _json


class GraphQLFederationConfiguration:
    def __init__(self,
                 enabled: bool = None,
                 serviceSdl: str = None
                 ):
        self.enabled = enabled
        self.serviceSdl = serviceSdl

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, GraphQLFederationConfiguration)
        return _json


class GraphQLSubscriptionConfiguration:
    def __init__(self,
                 enabled: bool = None,
                 url: 'ConfigurationVariable' = None,
                 useSSE: bool = None
                 ):
        self.enabled = enabled
        self.url = json_parser.parse_dict_to_class(url, ConfigurationVariable)
        self.useSSE = useSSE

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['url'] = self.url.to_json() if self.url else None
        json_parser.recover_dict_keys(_json, GraphQLSubscriptionConfiguration)
        return _json


class HTTPHeader:
    def __init__(self,
                 values: list['ConfigurationVariable'] = None
                 ):
        self.values = json_parser.parse_list_to_class(values, ConfigurationVariable)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['values'] = [x.to_json() for x in self.values] if self.values else None
        json_parser.recover_dict_keys(_json, HTTPHeader)
        return _json


class Health:
    def __init__(self,
                 report: 'HealthReport' = None,
                 status: str = None,
                 workdir: Optional[str] = None
                 ):
        self.report = json_parser.parse_dict_to_class(report, HealthReport)
        self.status = status
        self.workdir = workdir

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['report'] = self.report.to_json() if self.report else None
        json_parser.recover_dict_keys(_json, Health)
        return _json


class HealthReport:
    def __init__(self,
                 customizes: list[str] = None,
                 functions: list[str] = None,
                 proxys: list[str] = None,
                 time: datetime = None
                 ):
        self.customizes = customizes
        self.functions = functions
        self.proxys = proxys
        self.time = time

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, HealthReport)
        return _json


class HookFile:
    def __init__(self,
                 name: str = None,
                 provider: str = None,
                 size: int = None,
                 type: str = None
                 ):
        self.name = name
        self.provider = provider
        self.size = size
        self.type = type

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, HookFile)
        return _json


class JwksAuthProvider:
    def __init__(self,
                 issuer: 'ConfigurationVariable' = None,
                 jwksJson: 'ConfigurationVariable' = None,
                 userInfoCacheTtlSeconds: int = None
                 ):
        self.issuer = json_parser.parse_dict_to_class(issuer, ConfigurationVariable)
        self.jwksJson = json_parser.parse_dict_to_class(jwksJson, ConfigurationVariable)
        self.userInfoCacheTtlSeconds = userInfoCacheTtlSeconds

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['issuer'] = self.issuer.to_json() if self.issuer else None
        _json['jwksJson'] = self.jwksJson.to_json() if self.jwksJson else None
        json_parser.recover_dict_keys(_json, JwksAuthProvider)
        return _json


class JwksBasedAuthentication:
    def __init__(self,
                 providers: list['JwksAuthProvider'] = None
                 ):
        self.providers = json_parser.parse_list_to_class(providers, JwksAuthProvider)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['providers'] = [x.to_json() for x in self.providers] if self.providers else None
        json_parser.recover_dict_keys(_json, JwksBasedAuthentication)
        return _json


class JwtUpstreamAuthenticationConfig:
    def __init__(self,
                 secret: 'ConfigurationVariable' = None,
                 signingMethod: int = None
                 ):
        self.secret = json_parser.parse_dict_to_class(secret, ConfigurationVariable)
        self.signingMethod = signingMethod

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['secret'] = self.secret.to_json() if self.secret else None
        json_parser.recover_dict_keys(_json, JwtUpstreamAuthenticationConfig)
        return _json


class JwtUpstreamAuthenticationWithAccessTokenExchange:
    def __init__(self,
                 accessTokenExchangeEndpoint: 'ConfigurationVariable' = None,
                 secret: 'ConfigurationVariable' = None,
                 signingMethod: SigningMethod = None
                 ):
        self.accessTokenExchangeEndpoint = json_parser.parse_dict_to_class(accessTokenExchangeEndpoint,
                                                                           ConfigurationVariable)
        self.secret = json_parser.parse_dict_to_class(secret, ConfigurationVariable)
        self.signingMethod = signingMethod

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json[
            'accessTokenExchangeEndpoint'] = self.accessTokenExchangeEndpoint.to_json() if self.accessTokenExchangeEndpoint else None
        _json['secret'] = self.secret.to_json() if self.secret else None
        _json['signingMethod'] = self.signingMethod.value if self.signingMethod else None
        json_parser.recover_dict_keys(_json, JwtUpstreamAuthenticationWithAccessTokenExchange)
        return _json


class ListenerOptions:
    def __init__(self,
                 host: 'ConfigurationVariable' = None,
                 port: 'ConfigurationVariable' = None
                 ):
        self.host = json_parser.parse_dict_to_class(host, ConfigurationVariable)
        self.port = json_parser.parse_dict_to_class(port, ConfigurationVariable)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['host'] = self.host.to_json() if self.host else None
        _json['port'] = self.port.to_json() if self.port else None
        json_parser.recover_dict_keys(_json, ListenerOptions)
        return _json


class Location:
    def __init__(self,
                 column: int = None,
                 line: int = None
                 ):
        self.column = column
        self.line = line

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, Location)
        return _json


class MTLSConfiguration:
    def __init__(self,
                 cert: 'ConfigurationVariable' = None,
                 insecureSkipVerify: bool = None,
                 key: 'ConfigurationVariable' = None
                 ):
        self.cert = json_parser.parse_dict_to_class(cert, ConfigurationVariable)
        self.insecureSkipVerify = insecureSkipVerify
        self.key = json_parser.parse_dict_to_class(key, ConfigurationVariable)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['cert'] = self.cert.to_json() if self.cert else None
        _json['key'] = self.key.to_json() if self.key else None
        json_parser.recover_dict_keys(_json, MTLSConfiguration)
        return _json


class MiddlewareHookResponse:
    def __init__(self,
                 hook: MiddlewareHook = None,
                 input: object = None,
                 op: str = None,
                 response: object = None,
                 setClientRequestHeaders: 'RequestHeaders' = None,
                 error: Optional[str] = None
                 ):
        self.hook = hook
        self.input = input
        self.op = op
        self.response = response
        self.setClientRequestHeaders = json_parser.parse_dict_to_class(setClientRequestHeaders, RequestHeaders)
        self.error = error

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['hook'] = self.hook.value if self.hook else None
        _json[
            'setClientRequestHeaders'] = self.setClientRequestHeaders.to_json() if self.setClientRequestHeaders else None
        json_parser.recover_dict_keys(_json, MiddlewareHookResponse)
        return _json


class MockResolveHookConfiguration:
    def __init__(self,
                 enabled: bool = None,
                 subscriptionPollingIntervalMillis: int = None
                 ):
        self.enabled = enabled
        self.subscriptionPollingIntervalMillis = subscriptionPollingIntervalMillis

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, MockResolveHookConfiguration)
        return _json


class MutatingPostAuthenticationResponse:
    def __init__(self,
                 message: str = None,
                 status: str = None,
                 user: 'User' = None
                 ):
        self.message = message
        self.status = status
        self.user = json_parser.parse_dict_to_class(user, User)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['user'] = self.user.to_json() if self.user else None
        json_parser.recover_dict_keys(_json, MutatingPostAuthenticationResponse)
        return _json


class NodeLogging:
    def __init__(self,
                 level: 'ConfigurationVariable' = None
                 ):
        self.level = json_parser.parse_dict_to_class(level, ConfigurationVariable)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['level'] = self.level.to_json() if self.level else None
        json_parser.recover_dict_keys(_json, NodeLogging)
        return _json


class NodeOptions:
    def __init__(self,
                 defaultRequestTimeoutSeconds: int = None,
                 listen: 'ListenerOptions' = None,
                 logger: 'NodeLogging' = None,
                 nodeUrl: 'ConfigurationVariable' = None,
                 publicNodeUrl: 'ConfigurationVariable' = None
                 ):
        self.defaultRequestTimeoutSeconds = defaultRequestTimeoutSeconds
        self.listen = json_parser.parse_dict_to_class(listen, ListenerOptions)
        self.logger = json_parser.parse_dict_to_class(logger, NodeLogging)
        self.nodeUrl = json_parser.parse_dict_to_class(nodeUrl, ConfigurationVariable)
        self.publicNodeUrl = json_parser.parse_dict_to_class(publicNodeUrl, ConfigurationVariable)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['listen'] = self.listen.to_json() if self.listen else None
        _json['logger'] = self.logger.to_json() if self.logger else None
        _json['nodeUrl'] = self.nodeUrl.to_json() if self.nodeUrl else None
        _json['publicNodeUrl'] = self.publicNodeUrl.to_json() if self.publicNodeUrl else None
        json_parser.recover_dict_keys(_json, NodeOptions)
        return _json


class OnRequestHookPayload:
    def __init__(self,
                 argsAllowList: list[str] = None,
                 operationName: str = None,
                 operationType: OperationTypeString = None,
                 request: 'WunderGraphRequest' = None,
                 __wg: Optional['BaseRequestBodyWg'] = None
                 ):
        self.argsAllowList = argsAllowList
        self.operationName = operationName
        self.operationType = operationType
        self.request = json_parser.parse_dict_to_class(request, WunderGraphRequest)
        self.__wg = json_parser.parse_dict_to_class(__wg, BaseRequestBodyWg)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['operationType'] = self.operationType.value if self.operationType else None
        _json['request'] = self.request.to_json() if self.request else None
        _json['__wg'] = self.__wg.to_json() if self.__wg else None
        json_parser.recover_dict_keys(_json, OnRequestHookPayload)
        return _json


class OnRequestHookResponse:
    def __init__(self,
                 cancel: bool = None,
                 request: 'WunderGraphRequest' = None,
                 skip: bool = None
                 ):
        self.cancel = cancel
        self.request = json_parser.parse_dict_to_class(request, WunderGraphRequest)
        self.skip = skip

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['request'] = self.request.to_json() if self.request else None
        json_parser.recover_dict_keys(_json, OnRequestHookResponse)
        return _json


class OnResponseHookPayload:
    def __init__(self,
                 operationName: str = None,
                 operationType: OperationTypeString = None,
                 response: 'WunderGraphResponse' = None,
                 __wg: Optional['BaseRequestBodyWg'] = None
                 ):
        self.operationName = operationName
        self.operationType = operationType
        self.response = json_parser.parse_dict_to_class(response, WunderGraphResponse)
        self.__wg = json_parser.parse_dict_to_class(__wg, BaseRequestBodyWg)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['operationType'] = self.operationType.value if self.operationType else None
        _json['response'] = self.response.to_json() if self.response else None
        _json['__wg'] = self.__wg.to_json() if self.__wg else None
        json_parser.recover_dict_keys(_json, OnResponseHookPayload)
        return _json


class OnResponseHookResponse:
    def __init__(self,
                 cancel: bool = None,
                 response: 'WunderGraphResponse' = None,
                 skip: bool = None
                 ):
        self.cancel = cancel
        self.response = json_parser.parse_dict_to_class(response, WunderGraphResponse)
        self.skip = skip

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['response'] = self.response.to_json() if self.response else None
        json_parser.recover_dict_keys(_json, OnResponseHookResponse)
        return _json


class OnWsConnectionInitHookPayload:
    def __init__(self,
                 dataSourceId: str = None,
                 request: 'WunderGraphRequest' = None
                 ):
        self.dataSourceId = dataSourceId
        self.request = json_parser.parse_dict_to_class(request, WunderGraphRequest)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['request'] = self.request.to_json() if self.request else None
        json_parser.recover_dict_keys(_json, OnWsConnectionInitHookPayload)
        return _json


class OnWsConnectionInitHookResponse:
    def __init__(self,
                 payload: object = None
                 ):
        self.payload = payload

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, OnWsConnectionInitHookResponse)
        return _json


class OpenIDConnectAuthProviderConfig:
    def __init__(self,
                 clientId: 'ConfigurationVariable' = None,
                 clientSecret: 'ConfigurationVariable' = None,
                 issuer: 'ConfigurationVariable' = None,
                 queryParameters: list['OpenIDConnectQueryParameter'] = None
                 ):
        self.clientId = json_parser.parse_dict_to_class(clientId, ConfigurationVariable)
        self.clientSecret = json_parser.parse_dict_to_class(clientSecret, ConfigurationVariable)
        self.issuer = json_parser.parse_dict_to_class(issuer, ConfigurationVariable)
        self.queryParameters = json_parser.parse_list_to_class(queryParameters, OpenIDConnectQueryParameter)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['clientId'] = self.clientId.to_json() if self.clientId else None
        _json['clientSecret'] = self.clientSecret.to_json() if self.clientSecret else None
        _json['issuer'] = self.issuer.to_json() if self.issuer else None
        _json['queryParameters'] = [x.to_json() for x in self.queryParameters] if self.queryParameters else None
        json_parser.recover_dict_keys(_json, OpenIDConnectAuthProviderConfig)
        return _json


class OpenIDConnectQueryParameter:
    def __init__(self,
                 name: 'ConfigurationVariable' = None,
                 value: 'ConfigurationVariable' = None
                 ):
        self.name = json_parser.parse_dict_to_class(name, ConfigurationVariable)
        self.value = json_parser.parse_dict_to_class(value, ConfigurationVariable)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['name'] = self.name.to_json() if self.name else None
        _json['value'] = self.value.to_json() if self.value else None
        json_parser.recover_dict_keys(_json, OpenIDConnectQueryParameter)
        return _json


class Operation:
    def __init__(self,
                 authenticationConfig: 'OperationAuthenticationConfig' = None,
                 authorizationConfig: 'OperationAuthorizationConfig' = None,
                 cacheConfig: 'OperationCacheConfig' = None,
                 content: str = None,
                 datasourceQuotes: 'Operation_datasourceQuotes' = None,
                 engine: OperationExecutionEngine = None,
                 hooksConfiguration: 'OperationHooksConfiguration' = None,
                 internal: bool = None,
                 liveQueryConfig: 'OperationLiveQueryConfig' = None,
                 multipartForms: list['OperationMultipartForm'] = None,
                 name: str = None,
                 operationType: OperationType = None,
                 path: str = None,
                 postResolveTransformations: list['PostResolveTransformation'] = None,
                 rateLimit: 'OperationRateLimit' = None,
                 ruleExpressionExisted: bool = None,
                 semaphore: 'OperationSemaphore' = None,
                 transaction: 'OperationTransaction' = None,
                 variablesConfiguration: 'OperationVariablesConfiguration' = None,
                 hookVariableDefaultValues: Optional[bytes] = None,
                 injectedVariablesSchema: Optional[str] = None,
                 internalVariablesSchema: Optional[str] = None,
                 interpolationVariablesSchema: Optional[str] = None,
                 responseSchema: Optional[str] = None,
                 variablesSchema: Optional[str] = None
                 ):
        self.authenticationConfig = json_parser.parse_dict_to_class(authenticationConfig, OperationAuthenticationConfig)
        self.authorizationConfig = json_parser.parse_dict_to_class(authorizationConfig, OperationAuthorizationConfig)
        self.cacheConfig = json_parser.parse_dict_to_class(cacheConfig, OperationCacheConfig)
        self.content = content
        self.datasourceQuotes = json_parser.parse_dict_to_class(datasourceQuotes, Operation_datasourceQuotes)
        self.engine = engine
        self.hooksConfiguration = json_parser.parse_dict_to_class(hooksConfiguration, OperationHooksConfiguration)
        self.internal = internal
        self.liveQueryConfig = json_parser.parse_dict_to_class(liveQueryConfig, OperationLiveQueryConfig)
        self.multipartForms = json_parser.parse_list_to_class(multipartForms, OperationMultipartForm)
        self.name = name
        self.operationType = operationType
        self.path = path
        self.postResolveTransformations = json_parser.parse_list_to_class(postResolveTransformations,
                                                                          PostResolveTransformation)
        self.rateLimit = json_parser.parse_dict_to_class(rateLimit, OperationRateLimit)
        self.ruleExpressionExisted = ruleExpressionExisted
        self.semaphore = json_parser.parse_dict_to_class(semaphore, OperationSemaphore)
        self.transaction = json_parser.parse_dict_to_class(transaction, OperationTransaction)
        self.variablesConfiguration = json_parser.parse_dict_to_class(variablesConfiguration,
                                                                      OperationVariablesConfiguration)
        self.hookVariableDefaultValues = hookVariableDefaultValues
        self.injectedVariablesSchema = injectedVariablesSchema
        self.internalVariablesSchema = internalVariablesSchema
        self.interpolationVariablesSchema = interpolationVariablesSchema
        self.responseSchema = responseSchema
        self.variablesSchema = variablesSchema

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['authenticationConfig'] = self.authenticationConfig.to_json() if self.authenticationConfig else None
        _json['authorizationConfig'] = self.authorizationConfig.to_json() if self.authorizationConfig else None
        _json['cacheConfig'] = self.cacheConfig.to_json() if self.cacheConfig else None
        _json['datasourceQuotes'] = self.datasourceQuotes.to_json() if self.datasourceQuotes else None
        _json['engine'] = self.engine.value if self.engine else None
        _json['hooksConfiguration'] = self.hooksConfiguration.to_json() if self.hooksConfiguration else None
        _json['liveQueryConfig'] = self.liveQueryConfig.to_json() if self.liveQueryConfig else None
        _json['multipartForms'] = [x.to_json() for x in self.multipartForms] if self.multipartForms else None
        _json['operationType'] = self.operationType.value if self.operationType else None
        _json['postResolveTransformations'] = [x.to_json() for x in
                                               self.postResolveTransformations] if self.postResolveTransformations else None
        _json['rateLimit'] = self.rateLimit.to_json() if self.rateLimit else None
        _json['semaphore'] = self.semaphore.to_json() if self.semaphore else None
        _json['transaction'] = self.transaction.to_json() if self.transaction else None
        _json['variablesConfiguration'] = self.variablesConfiguration.to_json() if self.variablesConfiguration else None
        json_parser.recover_dict_keys(_json, Operation)
        return _json


class Operation_datasourceQuotes(dict[str, 'DatasourceQuote']):
    def __init__(self, *args, **kwargs):
        args = tuple([{k: json_parser.parse_dict_to_class(v, DatasourceQuote) for k, v in arg} for arg in args])
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        _json = {k: json_parser.recover_dict_keys(v.to_json(), DatasourceQuote) for k, v in _json.items()}
        return _json


class OperationAuthenticationConfig:
    def __init__(self,
                 authRequired: bool = None
                 ):
        self.authRequired = authRequired

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, OperationAuthenticationConfig)
        return _json


class OperationAuthorizationConfig:
    def __init__(self,
                 claims: list['ClaimConfig'] = None,
                 roleConfig: 'OperationRoleConfig' = None
                 ):
        self.claims = json_parser.parse_list_to_class(claims, ClaimConfig)
        self.roleConfig = json_parser.parse_dict_to_class(roleConfig, OperationRoleConfig)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['claims'] = [x.to_json() for x in self.claims] if self.claims else None
        _json['roleConfig'] = self.roleConfig.to_json() if self.roleConfig else None
        json_parser.recover_dict_keys(_json, OperationAuthorizationConfig)
        return _json


class OperationCacheConfig:
    def __init__(self,
                 enabled: bool = None,
                 maxAge: int = None,
                 public: bool = None,
                 staleWhileRevalidate: int = None
                 ):
        self.enabled = enabled
        self.maxAge = maxAge
        self.public = public
        self.staleWhileRevalidate = staleWhileRevalidate

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, OperationCacheConfig)
        return _json


class OperationHookPayload:
    def __init__(self,
                 canceled: bool = None,
                 hook: MiddlewareHook = None,
                 input: object = None,
                 op: str = None,
                 response: 'OperationHookPayload_response' = None,
                 setClientRequestHeaders: 'RequestHeaders' = None,
                 __wg: Optional['BaseRequestBodyWg'] = None
                 ):
        self.canceled = canceled
        self.hook = hook
        self.input = input
        self.op = op
        self.response = json_parser.parse_dict_to_class(response, OperationHookPayload_response)
        self.setClientRequestHeaders = json_parser.parse_dict_to_class(setClientRequestHeaders, RequestHeaders)
        self.__wg = json_parser.parse_dict_to_class(__wg, BaseRequestBodyWg)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['hook'] = self.hook.value if self.hook else None
        _json['response'] = self.response.to_json() if self.response else None
        _json[
            'setClientRequestHeaders'] = self.setClientRequestHeaders.to_json() if self.setClientRequestHeaders else None
        _json['__wg'] = self.__wg.to_json() if self.__wg else None
        json_parser.recover_dict_keys(_json, OperationHookPayload)
        return _json


class OperationHookPayload_response:
    def __init__(self,
                 data: object = None,
                 errors: list['RequestError'] = None
                 ):
        self.data = data
        self.errors = json_parser.parse_list_to_class(errors, RequestError)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['errors'] = [x.to_json() for x in self.errors] if self.errors else None
        json_parser.recover_dict_keys(_json, OperationHookPayload_response)
        return _json


class OperationHooksConfiguration:
    def __init__(self,
                 customResolve: bool = None,
                 httpTransportAfterResponse: bool = None,
                 httpTransportBeforeRequest: bool = None,
                 httpTransportOnRequest: bool = None,
                 httpTransportOnResponse: bool = None,
                 mockResolve: 'MockResolveHookConfiguration' = None,
                 mutatingPostResolve: bool = None,
                 mutatingPreResolve: bool = None,
                 onConnectionInit: bool = None,
                 postResolve: bool = None,
                 preResolve: bool = None
                 ):
        self.customResolve = customResolve
        self.httpTransportAfterResponse = httpTransportAfterResponse
        self.httpTransportBeforeRequest = httpTransportBeforeRequest
        self.httpTransportOnRequest = httpTransportOnRequest
        self.httpTransportOnResponse = httpTransportOnResponse
        self.mockResolve = json_parser.parse_dict_to_class(mockResolve, MockResolveHookConfiguration)
        self.mutatingPostResolve = mutatingPostResolve
        self.mutatingPreResolve = mutatingPreResolve
        self.onConnectionInit = onConnectionInit
        self.postResolve = postResolve
        self.preResolve = preResolve

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['mockResolve'] = self.mockResolve.to_json() if self.mockResolve else None
        json_parser.recover_dict_keys(_json, OperationHooksConfiguration)
        return _json


class OperationLiveQueryConfig:
    def __init__(self,
                 enabled: bool = None,
                 pollingIntervalSeconds: int = None
                 ):
        self.enabled = enabled
        self.pollingIntervalSeconds = pollingIntervalSeconds

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, OperationLiveQueryConfig)
        return _json


class OperationMultipartForm:
    def __init__(self,
                 fieldName: str = None,
                 isArray: bool = None
                 ):
        self.fieldName = fieldName
        self.isArray = isArray

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, OperationMultipartForm)
        return _json


class OperationRateLimit:
    def __init__(self,
                 enabled: bool = None,
                 perSecond: int = None,
                 requests: int = None
                 ):
        self.enabled = enabled
        self.perSecond = perSecond
        self.requests = requests

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, OperationRateLimit)
        return _json


class OperationRoleConfig:
    def __init__(self,
                 denyMatchAll: list[str] = None,
                 denyMatchAny: list[str] = None,
                 requireMatchAll: list[str] = None,
                 requireMatchAny: list[str] = None
                 ):
        self.denyMatchAll = denyMatchAll
        self.denyMatchAny = denyMatchAny
        self.requireMatchAll = requireMatchAll
        self.requireMatchAny = requireMatchAny

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, OperationRoleConfig)
        return _json


class OperationSemaphore:
    def __init__(self,
                 enabled: bool = None,
                 tickets: int = None,
                 timeoutSeconds: int = None
                 ):
        self.enabled = enabled
        self.tickets = tickets
        self.timeoutSeconds = timeoutSeconds

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, OperationSemaphore)
        return _json


class OperationTransaction:
    def __init__(self,
                 isolationLevel: int = None,
                 maxWaitSeconds: int = None,
                 timeoutSeconds: int = None
                 ):
        self.isolationLevel = isolationLevel
        self.maxWaitSeconds = maxWaitSeconds
        self.timeoutSeconds = timeoutSeconds

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, OperationTransaction)
        return _json


class OperationVariablesConfiguration:
    def __init__(self,
                 injectVariables: list['VariableInjectionConfiguration'] = None,
                 whereInputs: list['VariableWhereInputConfiguration'] = None
                 ):
        self.injectVariables = json_parser.parse_list_to_class(injectVariables, VariableInjectionConfiguration)
        self.whereInputs = json_parser.parse_list_to_class(whereInputs, VariableWhereInputConfiguration)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['injectVariables'] = [x.to_json() for x in self.injectVariables] if self.injectVariables else None
        _json['whereInputs'] = [x.to_json() for x in self.whereInputs] if self.whereInputs else None
        json_parser.recover_dict_keys(_json, OperationVariablesConfiguration)
        return _json


class PostResolveGetTransformation:
    def __init__(self,
                 from_: list[str] = None,
                 to: list[str] = None
                 ):
        self.from_ = from_
        self.to = to

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, PostResolveGetTransformation)
        return _json


class PostResolveTransformation:
    def __init__(self,
                 depth: int = None,
                 get: 'PostResolveGetTransformation' = None,
                 kind: PostResolveTransformationKind = None
                 ):
        self.depth = depth
        self.get = json_parser.parse_dict_to_class(get, PostResolveGetTransformation)
        self.kind = kind

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['get'] = self.get.to_json() if self.get else None
        _json['kind'] = self.kind.value if self.kind else None
        json_parser.recover_dict_keys(_json, PostResolveTransformation)
        return _json


class QuoteField:
    def __init__(self,
                 indexes: list[int] = None
                 ):
        self.indexes = indexes

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, QuoteField)
        return _json


class RESTSubscriptionConfiguration:
    def __init__(self,
                 enabled: bool = None,
                 pollingIntervalMillis: int = None,
                 skipPublishSameResponse: bool = None,
                 doneData: Optional[str] = None
                 ):
        self.enabled = enabled
        self.pollingIntervalMillis = pollingIntervalMillis
        self.skipPublishSameResponse = skipPublishSameResponse
        self.doneData = doneData

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, RESTSubscriptionConfiguration)
        return _json


class RequestError:
    def __init__(self,
                 message: str = None,
                 path: list[str] = None,
                 locations: Optional[list['Location']] = None
                 ):
        self.message = message
        self.path = path
        self.locations = json_parser.parse_list_to_class(locations, Location)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['locations'] = [x.to_json() for x in self.locations] if self.locations else None
        json_parser.recover_dict_keys(_json, RequestError)
        return _json


class RequestHeaders(dict[str, str]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        return _json


class S3UploadConfiguration:
    def __init__(self,
                 accessKeyID: 'ConfigurationVariable' = None,
                 bucketLocation: 'ConfigurationVariable' = None,
                 bucketName: 'ConfigurationVariable' = None,
                 endpoint: 'ConfigurationVariable' = None,
                 name: str = None,
                 secretAccessKey: 'ConfigurationVariable' = None,
                 uploadProfiles: 'S3UploadConfiguration_uploadProfiles' = None,
                 useSSL: bool = None
                 ):
        self.accessKeyID = json_parser.parse_dict_to_class(accessKeyID, ConfigurationVariable)
        self.bucketLocation = json_parser.parse_dict_to_class(bucketLocation, ConfigurationVariable)
        self.bucketName = json_parser.parse_dict_to_class(bucketName, ConfigurationVariable)
        self.endpoint = json_parser.parse_dict_to_class(endpoint, ConfigurationVariable)
        self.name = name
        self.secretAccessKey = json_parser.parse_dict_to_class(secretAccessKey, ConfigurationVariable)
        self.uploadProfiles = json_parser.parse_dict_to_class(uploadProfiles, S3UploadConfiguration_uploadProfiles)
        self.useSSL = useSSL

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['accessKeyID'] = self.accessKeyID.to_json() if self.accessKeyID else None
        _json['bucketLocation'] = self.bucketLocation.to_json() if self.bucketLocation else None
        _json['bucketName'] = self.bucketName.to_json() if self.bucketName else None
        _json['endpoint'] = self.endpoint.to_json() if self.endpoint else None
        _json['secretAccessKey'] = self.secretAccessKey.to_json() if self.secretAccessKey else None
        _json['uploadProfiles'] = self.uploadProfiles.to_json() if self.uploadProfiles else None
        json_parser.recover_dict_keys(_json, S3UploadConfiguration)
        return _json


class S3UploadConfiguration_uploadProfiles(dict[str, 'S3UploadProfile']):
    def __init__(self, *args, **kwargs):
        args = tuple([{k: json_parser.parse_dict_to_class(v, S3UploadProfile) for k, v in arg} for arg in args])
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        _json = {k: json_parser.recover_dict_keys(v.to_json(), S3UploadProfile) for k, v in _json.items()}
        return _json


class S3UploadProfile:
    def __init__(self,
                 allowedFileExtensions: list[str] = None,
                 allowedMimeTypes: list[str] = None,
                 hooks: 'S3UploadProfileHooksConfiguration' = None,
                 maxAllowedFiles: int = None,
                 maxAllowedUploadSizeBytes: int = None,
                 metadataJSONSchema: str = None,
                 requireAuthentication: bool = None
                 ):
        self.allowedFileExtensions = allowedFileExtensions
        self.allowedMimeTypes = allowedMimeTypes
        self.hooks = json_parser.parse_dict_to_class(hooks, S3UploadProfileHooksConfiguration)
        self.maxAllowedFiles = maxAllowedFiles
        self.maxAllowedUploadSizeBytes = maxAllowedUploadSizeBytes
        self.metadataJSONSchema = metadataJSONSchema
        self.requireAuthentication = requireAuthentication

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['hooks'] = self.hooks.to_json() if self.hooks else None
        json_parser.recover_dict_keys(_json, S3UploadProfile)
        return _json


class S3UploadProfileHooksConfiguration:
    def __init__(self,
                 postUpload: bool = None,
                 preUpload: bool = None
                 ):
        self.postUpload = postUpload
        self.preUpload = preUpload

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, S3UploadProfileHooksConfiguration)
        return _json


class ServerLogging:
    def __init__(self,
                 level: 'ConfigurationVariable' = None
                 ):
        self.level = json_parser.parse_dict_to_class(level, ConfigurationVariable)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['level'] = self.level.to_json() if self.level else None
        json_parser.recover_dict_keys(_json, ServerLogging)
        return _json


class ServerOptions:
    def __init__(self,
                 listen: 'ListenerOptions' = None,
                 logger: 'ServerLogging' = None,
                 serverUrl: 'ConfigurationVariable' = None
                 ):
        self.listen = json_parser.parse_dict_to_class(listen, ListenerOptions)
        self.logger = json_parser.parse_dict_to_class(logger, ServerLogging)
        self.serverUrl = json_parser.parse_dict_to_class(serverUrl, ConfigurationVariable)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['listen'] = self.listen.to_json() if self.listen else None
        _json['logger'] = self.logger.to_json() if self.logger else None
        _json['serverUrl'] = self.serverUrl.to_json() if self.serverUrl else None
        json_parser.recover_dict_keys(_json, ServerOptions)
        return _json


class SingleTypeField:
    def __init__(self,
                 fieldName: str = None,
                 typeName: str = None
                 ):
        self.fieldName = fieldName
        self.typeName = typeName

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, SingleTypeField)
        return _json


class StatusCodeTypeMapping:
    def __init__(self,
                 injectStatusCodeIntoBody: bool = None,
                 statusCode: int = None,
                 typeName: str = None
                 ):
        self.injectStatusCodeIntoBody = injectStatusCodeIntoBody
        self.statusCode = statusCode
        self.typeName = typeName

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, StatusCodeTypeMapping)
        return _json


class TypeConfiguration:
    def __init__(self,
                 renameTo: str = None,
                 typeName: str = None
                 ):
        self.renameTo = renameTo
        self.typeName = typeName

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, TypeConfiguration)
        return _json


class TypeField:
    def __init__(self,
                 fieldNames: list[str] = None,
                 typeName: str = None,
                 quotes: Optional['TypeField_quotes'] = None
                 ):
        self.fieldNames = fieldNames
        self.typeName = typeName
        self.quotes = json_parser.parse_dict_to_class(quotes, TypeField_quotes)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['quotes'] = self.quotes.to_json() if self.quotes else None
        json_parser.recover_dict_keys(_json, TypeField)
        return _json


class TypeField_quotes(dict[str, 'QuoteField']):
    def __init__(self, *args, **kwargs):
        args = tuple([{k: json_parser.parse_dict_to_class(v, QuoteField) for k, v in arg} for arg in args])
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        _json = {k: json_parser.recover_dict_keys(v.to_json(), QuoteField) for k, v in _json.items()}
        return _json


class URLQueryConfiguration:
    def __init__(self,
                 name: str = None,
                 value: str = None
                 ):
        self.name = name
        self.value = value

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, URLQueryConfiguration)
        return _json


class UploadHookPayload:
    def __init__(self,
                 error: 'UploadHookPayload_error' = None,
                 file: 'HookFile' = None,
                 meta: object = None,
                 __wg: Optional['BaseRequestBodyWg'] = None
                 ):
        self.error = json_parser.parse_dict_to_class(error, UploadHookPayload_error)
        self.file = json_parser.parse_dict_to_class(file, HookFile)
        self.meta = meta
        self.__wg = json_parser.parse_dict_to_class(__wg, BaseRequestBodyWg)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['error'] = self.error.to_json() if self.error else None
        _json['file'] = self.file.to_json() if self.file else None
        _json['__wg'] = self.__wg.to_json() if self.__wg else None
        json_parser.recover_dict_keys(_json, UploadHookPayload)
        return _json


class UploadHookPayload_error:
    def __init__(self,
                 message: str = None,
                 name: str = None
                 ):
        self.message = message
        self.name = name

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, UploadHookPayload_error)
        return _json


class UploadHookResponse:
    def __init__(self,
                 error: str = None,
                 fileKey: str = None
                 ):
        self.error = error
        self.fileKey = fileKey

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, UploadHookResponse)
        return _json


class UploadedFile:
    def __init__(self,
                 key: str = None
                 ):
        self.key = key

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        json_parser.recover_dict_keys(_json, UploadedFile)
        return _json


class UploadedFiles(list['UploadedFile']):
    def __init__(self, *args, **kwargs):
        args = tuple([[json_parser.parse_dict_to_class(v, UploadedFile) for v in arg] for arg in args])
        super().__init__(*args, **kwargs)

    def to_json(self) -> list:
        _json = self

        _json = [json_parser.recover_dict_keys(x.to_json(), UploadedFile) for x in _json]

        return _json


class UpstreamAuthentication:
    def __init__(self,
                 jwtConfig: 'JwtUpstreamAuthenticationConfig' = None,
                 jwtWithAccessTokenExchangeConfig: 'JwtUpstreamAuthenticationWithAccessTokenExchange' = None,
                 kind: UpstreamAuthenticationKind = None
                 ):
        self.jwtConfig = json_parser.parse_dict_to_class(jwtConfig, JwtUpstreamAuthenticationConfig)
        self.jwtWithAccessTokenExchangeConfig = json_parser.parse_dict_to_class(jwtWithAccessTokenExchangeConfig,
                                                                                JwtUpstreamAuthenticationWithAccessTokenExchange)
        self.kind = kind

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['jwtConfig'] = self.jwtConfig.to_json() if self.jwtConfig else None
        _json[
            'jwtWithAccessTokenExchangeConfig'] = self.jwtWithAccessTokenExchangeConfig.to_json() if self.jwtWithAccessTokenExchangeConfig else None
        _json['kind'] = self.kind.value if self.kind else None
        json_parser.recover_dict_keys(_json, UpstreamAuthentication)
        return _json


class User:
    def __init__(self,
                 roles: list[str] = None,
                 accessToken: Optional[object] = None,
                 birthDate: Optional[str] = None,
                 customAttributes: Optional[list[str]] = None,
                 customClaims: Optional['User_customClaims'] = None,
                 email: Optional[str] = None,
                 emailVerified: Optional[bool] = None,
                 etag: Optional[str] = None,
                 firstName: Optional[str] = None,
                 fromCookie: Optional[bool] = None,
                 gender: Optional[str] = None,
                 idToken: Optional[object] = None,
                 lastName: Optional[str] = None,
                 locale: Optional[str] = None,
                 location: Optional[str] = None,
                 middleName: Optional[str] = None,
                 name: Optional[str] = None,
                 nickName: Optional[str] = None,
                 picture: Optional[str] = None,
                 preferredUsername: Optional[str] = None,
                 profile: Optional[str] = None,
                 provider: Optional[str] = None,
                 providerId: Optional[str] = None,
                 rawAccessToken: Optional[str] = None,
                 rawIdToken: Optional[str] = None,
                 userId: Optional[str] = None,
                 website: Optional[str] = None,
                 zoneInfo: Optional[str] = None
                 ):
        self.roles = roles
        self.accessToken = accessToken
        self.birthDate = birthDate
        self.customAttributes = customAttributes
        self.customClaims = json_parser.parse_dict_to_class(customClaims, User_customClaims)
        self.email = email
        self.emailVerified = emailVerified
        self.etag = etag
        self.firstName = firstName
        self.fromCookie = fromCookie
        self.gender = gender
        self.idToken = idToken
        self.lastName = lastName
        self.locale = locale
        self.location = location
        self.middleName = middleName
        self.name = name
        self.nickName = nickName
        self.picture = picture
        self.preferredUsername = preferredUsername
        self.profile = profile
        self.provider = provider
        self.providerId = providerId
        self.rawAccessToken = rawAccessToken
        self.rawIdToken = rawIdToken
        self.userId = userId
        self.website = website
        self.zoneInfo = zoneInfo

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['customClaims'] = self.customClaims.to_json() if self.customClaims else None
        json_parser.recover_dict_keys(_json, User)
        return _json


class User_customClaims(dict[str, object]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def to_json(self) -> dict:
        _json = self

        return _json


class UserDefinedApi:
    def __init__(self,
                 allowedHostNames: list['ConfigurationVariable'] = None,
                 authenticationConfig: 'ApiAuthenticationConfig' = None,
                 corsConfiguration: 'CorsConfiguration' = None,
                 enableGraphqlEndpoint: bool = None,
                 engineConfiguration: 'EngineConfiguration' = None,
                 invalidOperationNames: list[str] = None,
                 nodeOptions: 'NodeOptions' = None,
                 operations: list['Operation'] = None,
                 s3UploadConfiguration: list['S3UploadConfiguration'] = None,
                 serverOptions: 'ServerOptions' = None,
                 webhooks: list['WebhookConfiguration'] = None
                 ):
        self.allowedHostNames = json_parser.parse_list_to_class(allowedHostNames, ConfigurationVariable)
        self.authenticationConfig = json_parser.parse_dict_to_class(authenticationConfig, ApiAuthenticationConfig)
        self.corsConfiguration = json_parser.parse_dict_to_class(corsConfiguration, CorsConfiguration)
        self.enableGraphqlEndpoint = enableGraphqlEndpoint
        self.engineConfiguration = json_parser.parse_dict_to_class(engineConfiguration, EngineConfiguration)
        self.invalidOperationNames = invalidOperationNames
        self.nodeOptions = json_parser.parse_dict_to_class(nodeOptions, NodeOptions)
        self.operations = json_parser.parse_list_to_class(operations, Operation)
        self.s3UploadConfiguration = json_parser.parse_list_to_class(s3UploadConfiguration, S3UploadConfiguration)
        self.serverOptions = json_parser.parse_dict_to_class(serverOptions, ServerOptions)
        self.webhooks = json_parser.parse_list_to_class(webhooks, WebhookConfiguration)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['allowedHostNames'] = [x.to_json() for x in self.allowedHostNames] if self.allowedHostNames else None
        _json['authenticationConfig'] = self.authenticationConfig.to_json() if self.authenticationConfig else None
        _json['corsConfiguration'] = self.corsConfiguration.to_json() if self.corsConfiguration else None
        _json['engineConfiguration'] = self.engineConfiguration.to_json() if self.engineConfiguration else None
        _json['nodeOptions'] = self.nodeOptions.to_json() if self.nodeOptions else None
        _json['operations'] = [x.to_json() for x in self.operations] if self.operations else None
        _json['s3UploadConfiguration'] = [x.to_json() for x in
                                          self.s3UploadConfiguration] if self.s3UploadConfiguration else None
        _json['serverOptions'] = self.serverOptions.to_json() if self.serverOptions else None
        _json['webhooks'] = [x.to_json() for x in self.webhooks] if self.webhooks else None
        json_parser.recover_dict_keys(_json, UserDefinedApi)
        return _json


class VariableInjectionConfiguration:
    def __init__(self,
                 valueTypeName: str = None,
                 variableKind: InjectVariableKind = None,
                 variablePathComponents: list[str] = None,
                 dateFormat: Optional[str] = None,
                 dateOffset: Optional['DateOffset'] = None,
                 dateToUnix: Optional[int] = None,
                 environmentVariableName: Optional[str] = None,
                 fromHeaderName: Optional[str] = None,
                 ruleExpression: Optional[str] = None
                 ):
        self.valueTypeName = valueTypeName
        self.variableKind = variableKind
        self.variablePathComponents = variablePathComponents
        self.dateFormat = dateFormat
        self.dateOffset = json_parser.parse_dict_to_class(dateOffset, DateOffset)
        self.dateToUnix = dateToUnix
        self.environmentVariableName = environmentVariableName
        self.fromHeaderName = fromHeaderName
        self.ruleExpression = ruleExpression

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['variableKind'] = self.variableKind.value if self.variableKind else None
        _json['dateOffset'] = self.dateOffset.to_json() if self.dateOffset else None
        json_parser.recover_dict_keys(_json, VariableInjectionConfiguration)
        return _json


class VariableWhereInput:
    def __init__(self,
                 filter: 'VariableWhereInputFilter' = None,
                 not_: 'VariableWhereInput' = None
                 ):
        self.filter = json_parser.parse_dict_to_class(filter, VariableWhereInputFilter)
        self.not_ = json_parser.parse_dict_to_class(not_, VariableWhereInput)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['filter'] = self.filter.to_json() if self.filter else None
        _json['not_'] = self.not_.to_json() if self.not_ else None
        json_parser.recover_dict_keys(_json, VariableWhereInput)
        return _json


class VariableWhereInputConfiguration:
    def __init__(self,
                 variablePathComponents: list[str] = None,
                 whereInput: 'VariableWhereInput' = None
                 ):
        self.variablePathComponents = variablePathComponents
        self.whereInput = json_parser.parse_dict_to_class(whereInput, VariableWhereInput)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['whereInput'] = self.whereInput.to_json() if self.whereInput else None
        json_parser.recover_dict_keys(_json, VariableWhereInputConfiguration)
        return _json


class VariableWhereInputFilter:
    def __init__(self,
                 field: str = None,
                 relation: 'VariableWhereInputRelationFilter' = None,
                 scalar: 'VariableWhereInputScalarFilter' = None
                 ):
        self.field = field
        self.relation = json_parser.parse_dict_to_class(relation, VariableWhereInputRelationFilter)
        self.scalar = json_parser.parse_dict_to_class(scalar, VariableWhereInputScalarFilter)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['relation'] = self.relation.to_json() if self.relation else None
        _json['scalar'] = self.scalar.to_json() if self.scalar else None
        json_parser.recover_dict_keys(_json, VariableWhereInputFilter)
        return _json


class VariableWhereInputRelationFilter:
    def __init__(self,
                 type: VariableWhereInputRelationFilterType = None,
                 where: 'VariableWhereInput' = None
                 ):
        self.type = type
        self.where = json_parser.parse_dict_to_class(where, VariableWhereInput)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['type'] = self.type.value if self.type else None
        _json['where'] = self.where.to_json() if self.where else None
        json_parser.recover_dict_keys(_json, VariableWhereInputRelationFilter)
        return _json


class VariableWhereInputScalarFilter:
    def __init__(self,
                 insensitive: bool = None,
                 type: VariableWhereInputScalarFilterType = None
                 ):
        self.insensitive = insensitive
        self.type = type

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['type'] = self.type.value if self.type else None
        json_parser.recover_dict_keys(_json, VariableWhereInputScalarFilter)
        return _json


class WebhookConfiguration:
    def __init__(self,
                 filePath: str = None,
                 name: str = None,
                 verifier: 'WebhookVerifier' = None
                 ):
        self.filePath = filePath
        self.name = name
        self.verifier = json_parser.parse_dict_to_class(verifier, WebhookVerifier)

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['verifier'] = self.verifier.to_json() if self.verifier else None
        json_parser.recover_dict_keys(_json, WebhookConfiguration)
        return _json


class WebhookVerifier:
    def __init__(self,
                 kind: WebhookVerifierKind = None,
                 secret: 'ConfigurationVariable' = None,
                 signatureHeader: str = None,
                 signatureHeaderPrefix: str = None
                 ):
        self.kind = kind
        self.secret = json_parser.parse_dict_to_class(secret, ConfigurationVariable)
        self.signatureHeader = signatureHeader
        self.signatureHeaderPrefix = signatureHeaderPrefix

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['kind'] = self.kind.value if self.kind else None
        _json['secret'] = self.secret.to_json() if self.secret else None
        json_parser.recover_dict_keys(_json, WebhookVerifier)
        return _json


class WunderGraphConfiguration:
    def __init__(self,
                 api: 'UserDefinedApi' = None,
                 apiId: Optional[str] = None,
                 apiName: Optional[str] = None,
                 dangerouslyEnableGraphQLEndpoint: Optional[bool] = None,
                 deploymentName: Optional[str] = None,
                 environmentIds: Optional[list[str]] = None
                 ):
        self.api = json_parser.parse_dict_to_class(api, UserDefinedApi)
        self.apiId = apiId
        self.apiName = apiName
        self.dangerouslyEnableGraphQLEndpoint = dangerouslyEnableGraphQLEndpoint
        self.deploymentName = deploymentName
        self.environmentIds = environmentIds

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['api'] = self.api.to_json() if self.api else None
        json_parser.recover_dict_keys(_json, WunderGraphConfiguration)
        return _json


class WunderGraphRequest:
    def __init__(self,
                 headers: 'RequestHeaders' = None,
                 method: str = None,
                 requestURI: str = None,
                 body: Optional[object] = None,
                 originBody: Optional[bytes] = None
                 ):
        self.headers = json_parser.parse_dict_to_class(headers, RequestHeaders)
        self.method = method
        self.requestURI = requestURI
        self.body = body
        self.originBody = originBody

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['headers'] = self.headers.to_json() if self.headers else None
        json_parser.recover_dict_keys(_json, WunderGraphRequest)
        return _json


class WunderGraphResponse:
    def __init__(self,
                 headers: 'RequestHeaders' = None,
                 method: str = None,
                 requestURI: str = None,
                 status: str = None,
                 statusCode: int = None,
                 body: Optional[object] = None,
                 originBody: Optional[bytes] = None
                 ):
        self.headers = json_parser.parse_dict_to_class(headers, RequestHeaders)
        self.method = method
        self.requestURI = requestURI
        self.status = status
        self.statusCode = statusCode
        self.body = body
        self.originBody = originBody

    def to_json(self) -> dict:
        _json = self.__dict__.copy()
        _json['headers'] = self.headers.to_json() if self.headers else None
        json_parser.recover_dict_keys(_json, WunderGraphResponse)
        return _json


def register_init_parameter_renames():
    json_parser.init_parameter_renames[PostResolveGetTransformation] = [
        json_parser.init_parameter_rename('from', 'from_')]
    json_parser.init_parameter_renames[VariableWhereInput] = [json_parser.init_parameter_rename('not', 'not_')]
    return
