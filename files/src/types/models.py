from datetime import datetime
from enum import Enum
from typing import Optional

from custom_py.src.utils import json_parser


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['cookieBased'] = self.cookieBased.to_dict() if self.cookieBased else None
        _dict['hooks'] = self.hooks.to_dict() if self.hooks else None
        _dict['jwksBased'] = self.jwksBased.to_dict() if self.jwksBased else None

        json_parser.recover_dict_keys(_dict, ApiAuthenticationConfig)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, ApiAuthenticationHooks)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['renderConfiguration'] = self.renderConfiguration.value if self.renderConfiguration else None
        _dict['sourceType'] = self.sourceType.value if self.sourceType else None

        json_parser.recover_dict_keys(_dict, ArgumentConfiguration)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['githubConfig'] = self.githubConfig.to_dict() if self.githubConfig else None
        _dict['kind'] = self.kind.value if self.kind else None
        _dict['oidcConfig'] = self.oidcConfig.to_dict() if self.oidcConfig else None

        json_parser.recover_dict_keys(_dict, AuthProvider)
        return _dict


class BaseRequestBody:
    def __init__(self,
                 __wg: Optional['BaseRequestBodyWg'] = None
                 ):
        self.__wg = json_parser.parse_dict_to_class(__wg, BaseRequestBodyWg)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['__wg'] = self.__wg.to_dict() if self.__wg else None

        json_parser.recover_dict_keys(_dict, BaseRequestBody)
        return _dict


class BaseRequestBodyWg:
    def __init__(self,
                 clientRequest: 'WunderGraphRequest' = None,
                 user: 'User' = None
                 ):
        self.clientRequest = json_parser.parse_dict_to_class(clientRequest, WunderGraphRequest)
        self.user = json_parser.parse_dict_to_class(user, User)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['clientRequest'] = self.clientRequest.to_dict() if self.clientRequest else None
        _dict['user'] = self.user.to_dict() if self.user else None

        json_parser.recover_dict_keys(_dict, BaseRequestBodyWg)
        return _dict


class ClaimConfig:
    def __init__(self,
                 claimType: ClaimType = None,
                 custom: 'CustomClaim' = None,
                 variablePathComponents: list[str] = None
                 ):
        self.claimType = claimType
        self.custom = json_parser.parse_dict_to_class(custom, CustomClaim)
        self.variablePathComponents = variablePathComponents

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['claimType'] = self.claimType.value if self.claimType else None
        _dict['custom'] = self.custom.to_dict() if self.custom else None

        json_parser.recover_dict_keys(_dict, ClaimConfig)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['kind'] = self.kind.value if self.kind else None

        json_parser.recover_dict_keys(_dict, ConfigurationVariable)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['authorizedRedirectUriRegexes'] = [x.to_dict() for x in
                                                 self.authorizedRedirectUriRegexes] if self.authorizedRedirectUriRegexes else None
        _dict['authorizedRedirectUris'] = [x.to_dict() for x in
                                           self.authorizedRedirectUris] if self.authorizedRedirectUris else None
        _dict['blockKey'] = self.blockKey.to_dict() if self.blockKey else None
        _dict['csrfSecret'] = self.csrfSecret.to_dict() if self.csrfSecret else None
        _dict['hashKey'] = self.hashKey.to_dict() if self.hashKey else None
        _dict['providers'] = [x.to_dict() for x in self.providers] if self.providers else None

        json_parser.recover_dict_keys(_dict, CookieBasedAuthentication)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['allowedOrigins'] = [x.to_dict() for x in self.allowedOrigins] if self.allowedOrigins else None

        json_parser.recover_dict_keys(_dict, CorsConfiguration)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['type'] = self.type.value if self.type else None

        json_parser.recover_dict_keys(_dict, CustomClaim)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['variables'] = self.variables.to_dict() if self.variables else None
        _dict['__wg'] = self.__wg.to_dict() if self.__wg else None

        json_parser.recover_dict_keys(_dict, CustomizeHookPayload)
        return _dict


class CustomizeHookPayload_variables(dict[str, object]):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, CustomizeHookPayload_variables)
        return _dict


class CustomizeHookResponse:
    def __init__(self,
                 data: object = None,
                 errors: list['RequestError'] = None,
                 extensions: 'CustomizeHookResponse_extensions' = None
                 ):
        self.data = data
        self.errors = json_parser.parse_list_to_class(errors, RequestError)
        self.extensions = json_parser.parse_dict_to_class(extensions, CustomizeHookResponse_extensions)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['errors'] = [x.to_dict() for x in self.errors] if self.errors else None
        _dict['extensions'] = self.extensions.to_dict() if self.extensions else None

        json_parser.recover_dict_keys(_dict, CustomizeHookResponse)
        return _dict


class CustomizeHookResponse_extensions(dict[str, object]):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, CustomizeHookResponse_extensions)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['childNodes'] = [x.to_dict() for x in self.childNodes] if self.childNodes else None
        _dict['customDatabase'] = self.customDatabase.to_dict() if self.customDatabase else None
        _dict['customGraphql'] = self.customGraphql.to_dict() if self.customGraphql else None
        _dict['customRest'] = self.customRest.to_dict() if self.customRest else None
        _dict['customStatic'] = self.customStatic.to_dict() if self.customStatic else None
        _dict['directives'] = [x.to_dict() for x in self.directives] if self.directives else None
        _dict['kind'] = self.kind.value if self.kind else None
        _dict['rootNodes'] = [x.to_dict() for x in self.rootNodes] if self.rootNodes else None
        _dict['customRestMap'] = self.customRestMap.to_dict() if self.customRestMap else None
        _dict[
            'customRestRequestRewriterMap'] = self.customRestRequestRewriterMap.to_dict() if self.customRestRequestRewriterMap else None
        _dict[
            'customRestResponseRewriterMap'] = self.customRestResponseRewriterMap.to_dict() if self.customRestResponseRewriterMap else None

        json_parser.recover_dict_keys(_dict, DataSourceConfiguration)
        return _dict


class DataSourceConfiguration_customRestMap(dict[str, 'DataSourceCustom_REST']):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, DataSourceConfiguration_customRestMap)
        return _dict


class DataSourceConfiguration_customRestRequestRewriterMap(dict[str, 'DataSourceCustom_REST_Rewriter']):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, DataSourceConfiguration_customRestRequestRewriterMap)
        return _dict


class DataSourceConfiguration_customRestResponseRewriterMap(dict[str, 'DataSourceCustom_REST_Rewriter']):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, DataSourceConfiguration_customRestResponseRewriterMap)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['databaseURL'] = self.databaseURL.to_dict() if self.databaseURL else None
        _dict['jsonTypeFields'] = [x.to_dict() for x in self.jsonTypeFields] if self.jsonTypeFields else None

        json_parser.recover_dict_keys(_dict, DataSourceCustom_Database)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['customScalarTypeFields'] = [x.to_dict() for x in
                                           self.customScalarTypeFields] if self.customScalarTypeFields else None
        _dict['federation'] = self.federation.to_dict() if self.federation else None
        _dict['fetch'] = self.fetch.to_dict() if self.fetch else None
        _dict['hooksConfiguration'] = self.hooksConfiguration.to_dict() if self.hooksConfiguration else None
        _dict['subscription'] = self.subscription.to_dict() if self.subscription else None

        json_parser.recover_dict_keys(_dict, DataSourceCustom_GraphQL)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['fetch'] = self.fetch.to_dict() if self.fetch else None
        _dict['statusCodeTypeMappings'] = [x.to_dict() for x in
                                           self.statusCodeTypeMappings] if self.statusCodeTypeMappings else None
        _dict['subscription'] = self.subscription.to_dict() if self.subscription else None
        _dict['requestRewriters'] = [x.to_dict() for x in self.requestRewriters] if self.requestRewriters else None
        _dict['responseExtractor'] = self.responseExtractor.to_dict() if self.responseExtractor else None
        _dict['responseRewriters'] = [x.to_dict() for x in self.responseRewriters] if self.responseRewriters else None

        json_parser.recover_dict_keys(_dict, DataSourceCustom_REST)
        return _dict


class DataSourceCustom_REST_Rewriter:
    def __init__(self,
                 rewriters: list['DataSourceRESTRewriter'] = None
                 ):
        self.rewriters = json_parser.parse_list_to_class(rewriters, DataSourceRESTRewriter)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['rewriters'] = [x.to_dict() for x in self.rewriters] if self.rewriters else None

        json_parser.recover_dict_keys(_dict, DataSourceCustom_REST_Rewriter)
        return _dict


class DataSourceCustom_Static:
    def __init__(self,
                 data: 'ConfigurationVariable' = None
                 ):
        self.data = json_parser.parse_dict_to_class(data, ConfigurationVariable)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['data'] = self.data.to_dict() if self.data else None

        json_parser.recover_dict_keys(_dict, DataSourceCustom_Static)
        return _dict


class DataSourceRESTResponseExtractor:
    def __init__(self,
                 errorMessageJsonpath: str = None,
                 statusCodeJsonpath: str = None,
                 statusCodeScopes: list['DataSourceRESTResponseStatusCodeScope'] = None
                 ):
        self.errorMessageJsonpath = errorMessageJsonpath
        self.statusCodeJsonpath = statusCodeJsonpath
        self.statusCodeScopes = json_parser.parse_list_to_class(statusCodeScopes, DataSourceRESTResponseStatusCodeScope)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['statusCodeScopes'] = [x.to_dict() for x in self.statusCodeScopes] if self.statusCodeScopes else None

        json_parser.recover_dict_keys(_dict, DataSourceRESTResponseExtractor)
        return _dict


class DataSourceRESTResponseStatusCodeScope:
    def __init__(self,
                 max: int = None,
                 min: int = None
                 ):
        self.max = max
        self.min = min

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, DataSourceRESTResponseStatusCodeScope)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict[
            'applySubCommonFieldValues'] = self.applySubCommonFieldValues.to_dict() if self.applySubCommonFieldValues else None
        _dict['applySubFieldTypes'] = [x.to_dict() for x in
                                       self.applySubFieldTypes] if self.applySubFieldTypes else None
        _dict['applySubObjects'] = [x.to_dict() for x in self.applySubObjects] if self.applySubObjects else None
        _dict['valueRewrites'] = self.valueRewrites.to_dict() if self.valueRewrites else None

        json_parser.recover_dict_keys(_dict, DataSourceRESTRewriter)
        return _dict


class DataSourceRESTRewriter_applySubCommonFieldValues(dict[str, str]):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, DataSourceRESTRewriter_applySubCommonFieldValues)
        return _dict


class DataSourceRESTRewriter_valueRewrites(dict[str, str]):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, DataSourceRESTRewriter_valueRewrites)
        return _dict


class DataSourceRESTSubObject:
    def __init__(self,
                 fields: list['DataSourceRESTSubfield'] = None,
                 name: str = None
                 ):
        self.fields = json_parser.parse_list_to_class(fields, DataSourceRESTSubfield)
        self.name = name

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['fields'] = [x.to_dict() for x in self.fields] if self.fields else None

        json_parser.recover_dict_keys(_dict, DataSourceRESTSubObject)
        return _dict


class DataSourceRESTSubfield:
    def __init__(self,
                 name: str = None,
                 type: int = None
                 ):
        self.name = name
        self.type = type

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, DataSourceRESTSubfield)
        return _dict


class DatasourceQuote:
    def __init__(self,
                 fields: list[str] = None
                 ):
        self.fields = fields

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, DatasourceQuote)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['unit'] = self.unit.value if self.unit else None

        json_parser.recover_dict_keys(_dict, DateOffset)
        return _dict


class DirectiveConfiguration:
    def __init__(self,
                 directiveName: str = None,
                 renameTo: str = None
                 ):
        self.directiveName = directiveName
        self.renameTo = renameTo

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, DirectiveConfiguration)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['datasourceConfigurations'] = [x.to_dict() for x in
                                             self.datasourceConfigurations] if self.datasourceConfigurations else None
        _dict['fieldConfigurations'] = [x.to_dict() for x in
                                        self.fieldConfigurations] if self.fieldConfigurations else None
        _dict['typeConfigurations'] = [x.to_dict() for x in
                                       self.typeConfigurations] if self.typeConfigurations else None

        json_parser.recover_dict_keys(_dict, EngineConfiguration)
        return _dict


class ErrorPath:
    def __init__(self):
        pass

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, ErrorPath)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['baseUrl'] = self.baseUrl.to_dict() if self.baseUrl else None
        _dict['body'] = self.body.to_dict() if self.body else None
        _dict['header'] = self.header.to_dict() if self.header else None
        _dict['mTLS'] = self.mTLS.to_dict() if self.mTLS else None
        _dict['method'] = self.method.value if self.method else None
        _dict['path'] = self.path.to_dict() if self.path else None
        _dict['query'] = [x.to_dict() for x in self.query] if self.query else None
        _dict['upstreamAuthentication'] = self.upstreamAuthentication.to_dict() if self.upstreamAuthentication else None
        _dict['url'] = self.url.to_dict() if self.url else None

        json_parser.recover_dict_keys(_dict, FetchConfiguration)
        return _dict


class FetchConfiguration_header(dict[str, 'HTTPHeader']):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, FetchConfiguration_header)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['argumentsConfiguration'] = [x.to_dict() for x in
                                           self.argumentsConfiguration] if self.argumentsConfiguration else None

        json_parser.recover_dict_keys(_dict, FieldConfiguration)
        return _dict


class GithubAuthProviderConfig:
    def __init__(self,
                 clientId: 'ConfigurationVariable' = None,
                 clientSecret: 'ConfigurationVariable' = None
                 ):
        self.clientId = json_parser.parse_dict_to_class(clientId, ConfigurationVariable)
        self.clientSecret = json_parser.parse_dict_to_class(clientSecret, ConfigurationVariable)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['clientId'] = self.clientId.to_dict() if self.clientId else None
        _dict['clientSecret'] = self.clientSecret.to_dict() if self.clientSecret else None

        json_parser.recover_dict_keys(_dict, GithubAuthProviderConfig)
        return _dict


class GraphQLDataSourceHooksConfiguration:
    def __init__(self,
                 onWSTransportConnectionInit: bool = None
                 ):
        self.onWSTransportConnectionInit = onWSTransportConnectionInit

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, GraphQLDataSourceHooksConfiguration)
        return _dict


class GraphQLFederationConfiguration:
    def __init__(self,
                 enabled: bool = None,
                 serviceSdl: str = None
                 ):
        self.enabled = enabled
        self.serviceSdl = serviceSdl

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, GraphQLFederationConfiguration)
        return _dict


class GraphQLSubscriptionConfiguration:
    def __init__(self,
                 enabled: bool = None,
                 url: 'ConfigurationVariable' = None,
                 useSSE: bool = None
                 ):
        self.enabled = enabled
        self.url = json_parser.parse_dict_to_class(url, ConfigurationVariable)
        self.useSSE = useSSE

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['url'] = self.url.to_dict() if self.url else None

        json_parser.recover_dict_keys(_dict, GraphQLSubscriptionConfiguration)
        return _dict


class HTTPHeader:
    def __init__(self,
                 values: list['ConfigurationVariable'] = None
                 ):
        self.values = json_parser.parse_list_to_class(values, ConfigurationVariable)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['values'] = [x.to_dict() for x in self.values] if self.values else None

        json_parser.recover_dict_keys(_dict, HTTPHeader)
        return _dict


class Health:
    def __init__(self,
                 report: 'HealthReport' = None,
                 status: str = None,
                 workdir: Optional[str] = None
                 ):
        self.report = json_parser.parse_dict_to_class(report, HealthReport)
        self.status = status
        self.workdir = workdir

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['report'] = self.report.to_dict() if self.report else None

        json_parser.recover_dict_keys(_dict, Health)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, HealthReport)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, HookFile)
        return _dict


class JwksAuthProvider:
    def __init__(self,
                 issuer: 'ConfigurationVariable' = None,
                 jwksJson: 'ConfigurationVariable' = None,
                 userInfoCacheTtlSeconds: int = None
                 ):
        self.issuer = json_parser.parse_dict_to_class(issuer, ConfigurationVariable)
        self.jwksJson = json_parser.parse_dict_to_class(jwksJson, ConfigurationVariable)
        self.userInfoCacheTtlSeconds = userInfoCacheTtlSeconds

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['issuer'] = self.issuer.to_dict() if self.issuer else None
        _dict['jwksJson'] = self.jwksJson.to_dict() if self.jwksJson else None

        json_parser.recover_dict_keys(_dict, JwksAuthProvider)
        return _dict


class JwksBasedAuthentication:
    def __init__(self,
                 providers: list['JwksAuthProvider'] = None
                 ):
        self.providers = json_parser.parse_list_to_class(providers, JwksAuthProvider)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['providers'] = [x.to_dict() for x in self.providers] if self.providers else None

        json_parser.recover_dict_keys(_dict, JwksBasedAuthentication)
        return _dict


class JwtUpstreamAuthenticationConfig:
    def __init__(self,
                 secret: 'ConfigurationVariable' = None,
                 signingMethod: int = None
                 ):
        self.secret = json_parser.parse_dict_to_class(secret, ConfigurationVariable)
        self.signingMethod = signingMethod

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['secret'] = self.secret.to_dict() if self.secret else None

        json_parser.recover_dict_keys(_dict, JwtUpstreamAuthenticationConfig)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict[
            'accessTokenExchangeEndpoint'] = self.accessTokenExchangeEndpoint.to_dict() if self.accessTokenExchangeEndpoint else None
        _dict['secret'] = self.secret.to_dict() if self.secret else None
        _dict['signingMethod'] = self.signingMethod.value if self.signingMethod else None

        json_parser.recover_dict_keys(_dict, JwtUpstreamAuthenticationWithAccessTokenExchange)
        return _dict


class ListenerOptions:
    def __init__(self,
                 host: 'ConfigurationVariable' = None,
                 port: 'ConfigurationVariable' = None
                 ):
        self.host = json_parser.parse_dict_to_class(host, ConfigurationVariable)
        self.port = json_parser.parse_dict_to_class(port, ConfigurationVariable)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['host'] = self.host.to_dict() if self.host else None
        _dict['port'] = self.port.to_dict() if self.port else None

        json_parser.recover_dict_keys(_dict, ListenerOptions)
        return _dict


class Location:
    def __init__(self,
                 column: int = None,
                 line: int = None
                 ):
        self.column = column
        self.line = line

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, Location)
        return _dict


class MTLSConfiguration:
    def __init__(self,
                 cert: 'ConfigurationVariable' = None,
                 insecureSkipVerify: bool = None,
                 key: 'ConfigurationVariable' = None
                 ):
        self.cert = json_parser.parse_dict_to_class(cert, ConfigurationVariable)
        self.insecureSkipVerify = insecureSkipVerify
        self.key = json_parser.parse_dict_to_class(key, ConfigurationVariable)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['cert'] = self.cert.to_dict() if self.cert else None
        _dict['key'] = self.key.to_dict() if self.key else None

        json_parser.recover_dict_keys(_dict, MTLSConfiguration)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['hook'] = self.hook.value if self.hook else None
        _dict[
            'setClientRequestHeaders'] = self.setClientRequestHeaders.to_dict() if self.setClientRequestHeaders else None

        json_parser.recover_dict_keys(_dict, MiddlewareHookResponse)
        return _dict


class MockResolveHookConfiguration:
    def __init__(self,
                 enabled: bool = None,
                 subscriptionPollingIntervalMillis: int = None
                 ):
        self.enabled = enabled
        self.subscriptionPollingIntervalMillis = subscriptionPollingIntervalMillis

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, MockResolveHookConfiguration)
        return _dict


class MutatingPostAuthenticationResponse:
    def __init__(self,
                 message: str = None,
                 status: str = None,
                 user: 'User' = None
                 ):
        self.message = message
        self.status = status
        self.user = json_parser.parse_dict_to_class(user, User)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['user'] = self.user.to_dict() if self.user else None

        json_parser.recover_dict_keys(_dict, MutatingPostAuthenticationResponse)
        return _dict


class NodeLogging:
    def __init__(self,
                 level: 'ConfigurationVariable' = None
                 ):
        self.level = json_parser.parse_dict_to_class(level, ConfigurationVariable)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['level'] = self.level.to_dict() if self.level else None

        json_parser.recover_dict_keys(_dict, NodeLogging)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['listen'] = self.listen.to_dict() if self.listen else None
        _dict['logger'] = self.logger.to_dict() if self.logger else None
        _dict['nodeUrl'] = self.nodeUrl.to_dict() if self.nodeUrl else None
        _dict['publicNodeUrl'] = self.publicNodeUrl.to_dict() if self.publicNodeUrl else None

        json_parser.recover_dict_keys(_dict, NodeOptions)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['operationType'] = self.operationType.value if self.operationType else None
        _dict['request'] = self.request.to_dict() if self.request else None
        _dict['__wg'] = self.__wg.to_dict() if self.__wg else None

        json_parser.recover_dict_keys(_dict, OnRequestHookPayload)
        return _dict


class OnRequestHookResponse:
    def __init__(self,
                 cancel: bool = None,
                 request: 'WunderGraphRequest' = None,
                 skip: bool = None
                 ):
        self.cancel = cancel
        self.request = json_parser.parse_dict_to_class(request, WunderGraphRequest)
        self.skip = skip

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['request'] = self.request.to_dict() if self.request else None

        json_parser.recover_dict_keys(_dict, OnRequestHookResponse)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['operationType'] = self.operationType.value if self.operationType else None
        _dict['response'] = self.response.to_dict() if self.response else None
        _dict['__wg'] = self.__wg.to_dict() if self.__wg else None

        json_parser.recover_dict_keys(_dict, OnResponseHookPayload)
        return _dict


class OnResponseHookResponse:
    def __init__(self,
                 cancel: bool = None,
                 response: 'WunderGraphResponse' = None,
                 skip: bool = None
                 ):
        self.cancel = cancel
        self.response = json_parser.parse_dict_to_class(response, WunderGraphResponse)
        self.skip = skip

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['response'] = self.response.to_dict() if self.response else None

        json_parser.recover_dict_keys(_dict, OnResponseHookResponse)
        return _dict


class OnWsConnectionInitHookPayload:
    def __init__(self,
                 dataSourceId: str = None,
                 request: 'WunderGraphRequest' = None
                 ):
        self.dataSourceId = dataSourceId
        self.request = json_parser.parse_dict_to_class(request, WunderGraphRequest)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['request'] = self.request.to_dict() if self.request else None

        json_parser.recover_dict_keys(_dict, OnWsConnectionInitHookPayload)
        return _dict


class OnWsConnectionInitHookResponse:
    def __init__(self,
                 payload: object = None
                 ):
        self.payload = payload

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, OnWsConnectionInitHookResponse)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['clientId'] = self.clientId.to_dict() if self.clientId else None
        _dict['clientSecret'] = self.clientSecret.to_dict() if self.clientSecret else None
        _dict['issuer'] = self.issuer.to_dict() if self.issuer else None
        _dict['queryParameters'] = [x.to_dict() for x in self.queryParameters] if self.queryParameters else None

        json_parser.recover_dict_keys(_dict, OpenIDConnectAuthProviderConfig)
        return _dict


class OpenIDConnectQueryParameter:
    def __init__(self,
                 name: 'ConfigurationVariable' = None,
                 value: 'ConfigurationVariable' = None
                 ):
        self.name = json_parser.parse_dict_to_class(name, ConfigurationVariable)
        self.value = json_parser.parse_dict_to_class(value, ConfigurationVariable)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['name'] = self.name.to_dict() if self.name else None
        _dict['value'] = self.value.to_dict() if self.value else None

        json_parser.recover_dict_keys(_dict, OpenIDConnectQueryParameter)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['authenticationConfig'] = self.authenticationConfig.to_dict() if self.authenticationConfig else None
        _dict['authorizationConfig'] = self.authorizationConfig.to_dict() if self.authorizationConfig else None
        _dict['cacheConfig'] = self.cacheConfig.to_dict() if self.cacheConfig else None
        _dict['datasourceQuotes'] = self.datasourceQuotes.to_dict() if self.datasourceQuotes else None
        _dict['engine'] = self.engine.value if self.engine else None
        _dict['hooksConfiguration'] = self.hooksConfiguration.to_dict() if self.hooksConfiguration else None
        _dict['liveQueryConfig'] = self.liveQueryConfig.to_dict() if self.liveQueryConfig else None
        _dict['multipartForms'] = [x.to_dict() for x in self.multipartForms] if self.multipartForms else None
        _dict['operationType'] = self.operationType.value if self.operationType else None
        _dict['postResolveTransformations'] = [x.to_dict() for x in
                                               self.postResolveTransformations] if self.postResolveTransformations else None
        _dict['rateLimit'] = self.rateLimit.to_dict() if self.rateLimit else None
        _dict['semaphore'] = self.semaphore.to_dict() if self.semaphore else None
        _dict['transaction'] = self.transaction.to_dict() if self.transaction else None
        _dict['variablesConfiguration'] = self.variablesConfiguration.to_dict() if self.variablesConfiguration else None

        json_parser.recover_dict_keys(_dict, Operation)
        return _dict


class Operation_datasourceQuotes(dict[str, 'DatasourceQuote']):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, Operation_datasourceQuotes)
        return _dict


class OperationAuthenticationConfig:
    def __init__(self,
                 authRequired: bool = None
                 ):
        self.authRequired = authRequired

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, OperationAuthenticationConfig)
        return _dict


class OperationAuthorizationConfig:
    def __init__(self,
                 claims: list['ClaimConfig'] = None,
                 roleConfig: 'OperationRoleConfig' = None
                 ):
        self.claims = json_parser.parse_list_to_class(claims, ClaimConfig)
        self.roleConfig = json_parser.parse_dict_to_class(roleConfig, OperationRoleConfig)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['claims'] = [x.to_dict() for x in self.claims] if self.claims else None
        _dict['roleConfig'] = self.roleConfig.to_dict() if self.roleConfig else None

        json_parser.recover_dict_keys(_dict, OperationAuthorizationConfig)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, OperationCacheConfig)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['hook'] = self.hook.value if self.hook else None
        _dict['response'] = self.response.to_dict() if self.response else None
        _dict[
            'setClientRequestHeaders'] = self.setClientRequestHeaders.to_dict() if self.setClientRequestHeaders else None
        _dict['__wg'] = self.__wg.to_dict() if self.__wg else None

        json_parser.recover_dict_keys(_dict, OperationHookPayload)
        return _dict


class OperationHookPayload_response:
    def __init__(self,
                 data: object = None,
                 errors: list['RequestError'] = None
                 ):
        self.data = data
        self.errors = json_parser.parse_list_to_class(errors, RequestError)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['errors'] = [x.to_dict() for x in self.errors] if self.errors else None

        json_parser.recover_dict_keys(_dict, OperationHookPayload_response)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['mockResolve'] = self.mockResolve.to_dict() if self.mockResolve else None

        json_parser.recover_dict_keys(_dict, OperationHooksConfiguration)
        return _dict


class OperationLiveQueryConfig:
    def __init__(self,
                 enabled: bool = None,
                 pollingIntervalSeconds: int = None
                 ):
        self.enabled = enabled
        self.pollingIntervalSeconds = pollingIntervalSeconds

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, OperationLiveQueryConfig)
        return _dict


class OperationMultipartForm:
    def __init__(self,
                 fieldName: str = None,
                 isArray: bool = None
                 ):
        self.fieldName = fieldName
        self.isArray = isArray

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, OperationMultipartForm)
        return _dict


class OperationRateLimit:
    def __init__(self,
                 enabled: bool = None,
                 perSecond: int = None,
                 requests: int = None
                 ):
        self.enabled = enabled
        self.perSecond = perSecond
        self.requests = requests

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, OperationRateLimit)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, OperationRoleConfig)
        return _dict


class OperationSemaphore:
    def __init__(self,
                 enabled: bool = None,
                 tickets: int = None,
                 timeoutSeconds: int = None
                 ):
        self.enabled = enabled
        self.tickets = tickets
        self.timeoutSeconds = timeoutSeconds

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, OperationSemaphore)
        return _dict


class OperationTransaction:
    def __init__(self,
                 isolationLevel: int = None,
                 maxWaitSeconds: int = None,
                 timeoutSeconds: int = None
                 ):
        self.isolationLevel = isolationLevel
        self.maxWaitSeconds = maxWaitSeconds
        self.timeoutSeconds = timeoutSeconds

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, OperationTransaction)
        return _dict


class OperationVariablesConfiguration:
    def __init__(self,
                 injectVariables: list['VariableInjectionConfiguration'] = None,
                 whereInputs: list['VariableWhereInputConfiguration'] = None
                 ):
        self.injectVariables = json_parser.parse_list_to_class(injectVariables, VariableInjectionConfiguration)
        self.whereInputs = json_parser.parse_list_to_class(whereInputs, VariableWhereInputConfiguration)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['injectVariables'] = [x.to_dict() for x in self.injectVariables] if self.injectVariables else None
        _dict['whereInputs'] = [x.to_dict() for x in self.whereInputs] if self.whereInputs else None

        json_parser.recover_dict_keys(_dict, OperationVariablesConfiguration)
        return _dict


class PostResolveGetTransformation:
    def __init__(self,
                 from_: list[str] = None,
                 to: list[str] = None
                 ):
        self.from_ = from_
        self.to = to

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, PostResolveGetTransformation)
        return _dict


class PostResolveTransformation:
    def __init__(self,
                 depth: int = None,
                 get: 'PostResolveGetTransformation' = None,
                 kind: PostResolveTransformationKind = None
                 ):
        self.depth = depth
        self.get = json_parser.parse_dict_to_class(get, PostResolveGetTransformation)
        self.kind = kind

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['get'] = self.get.to_dict() if self.get else None
        _dict['kind'] = self.kind.value if self.kind else None

        json_parser.recover_dict_keys(_dict, PostResolveTransformation)
        return _dict


class QuoteField:
    def __init__(self,
                 indexes: list[int] = None
                 ):
        self.indexes = indexes

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, QuoteField)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, RESTSubscriptionConfiguration)
        return _dict


class RequestError:
    def __init__(self,
                 message: str = None,
                 path: list[str] = None,
                 locations: Optional[list['Location']] = None
                 ):
        self.message = message
        self.path = path
        self.locations = json_parser.parse_list_to_class(locations, Location)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['locations'] = [x.to_dict() for x in self.locations] if self.locations else None

        json_parser.recover_dict_keys(_dict, RequestError)
        return _dict


class RequestHeaders(dict[str, str]):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, RequestHeaders)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['accessKeyID'] = self.accessKeyID.to_dict() if self.accessKeyID else None
        _dict['bucketLocation'] = self.bucketLocation.to_dict() if self.bucketLocation else None
        _dict['bucketName'] = self.bucketName.to_dict() if self.bucketName else None
        _dict['endpoint'] = self.endpoint.to_dict() if self.endpoint else None
        _dict['secretAccessKey'] = self.secretAccessKey.to_dict() if self.secretAccessKey else None
        _dict['uploadProfiles'] = self.uploadProfiles.to_dict() if self.uploadProfiles else None

        json_parser.recover_dict_keys(_dict, S3UploadConfiguration)
        return _dict


class S3UploadConfiguration_uploadProfiles(dict[str, 'S3UploadProfile']):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, S3UploadConfiguration_uploadProfiles)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['hooks'] = self.hooks.to_dict() if self.hooks else None

        json_parser.recover_dict_keys(_dict, S3UploadProfile)
        return _dict


class S3UploadProfileHooksConfiguration:
    def __init__(self,
                 postUpload: bool = None,
                 preUpload: bool = None
                 ):
        self.postUpload = postUpload
        self.preUpload = preUpload

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, S3UploadProfileHooksConfiguration)
        return _dict


class ServerLogging:
    def __init__(self,
                 level: 'ConfigurationVariable' = None
                 ):
        self.level = json_parser.parse_dict_to_class(level, ConfigurationVariable)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['level'] = self.level.to_dict() if self.level else None

        json_parser.recover_dict_keys(_dict, ServerLogging)
        return _dict


class ServerOptions:
    def __init__(self,
                 listen: 'ListenerOptions' = None,
                 logger: 'ServerLogging' = None,
                 serverUrl: 'ConfigurationVariable' = None
                 ):
        self.listen = json_parser.parse_dict_to_class(listen, ListenerOptions)
        self.logger = json_parser.parse_dict_to_class(logger, ServerLogging)
        self.serverUrl = json_parser.parse_dict_to_class(serverUrl, ConfigurationVariable)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['listen'] = self.listen.to_dict() if self.listen else None
        _dict['logger'] = self.logger.to_dict() if self.logger else None
        _dict['serverUrl'] = self.serverUrl.to_dict() if self.serverUrl else None

        json_parser.recover_dict_keys(_dict, ServerOptions)
        return _dict


class SingleTypeField:
    def __init__(self,
                 fieldName: str = None,
                 typeName: str = None
                 ):
        self.fieldName = fieldName
        self.typeName = typeName

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, SingleTypeField)
        return _dict


class StatusCodeTypeMapping:
    def __init__(self,
                 injectStatusCodeIntoBody: bool = None,
                 statusCode: int = None,
                 typeName: str = None
                 ):
        self.injectStatusCodeIntoBody = injectStatusCodeIntoBody
        self.statusCode = statusCode
        self.typeName = typeName

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, StatusCodeTypeMapping)
        return _dict


class TypeConfiguration:
    def __init__(self,
                 renameTo: str = None,
                 typeName: str = None
                 ):
        self.renameTo = renameTo
        self.typeName = typeName

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, TypeConfiguration)
        return _dict


class TypeField:
    def __init__(self,
                 fieldNames: list[str] = None,
                 typeName: str = None,
                 quotes: Optional['TypeField_quotes'] = None
                 ):
        self.fieldNames = fieldNames
        self.typeName = typeName
        self.quotes = json_parser.parse_dict_to_class(quotes, TypeField_quotes)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['quotes'] = self.quotes.to_dict() if self.quotes else None

        json_parser.recover_dict_keys(_dict, TypeField)
        return _dict


class TypeField_quotes(dict[str, 'QuoteField']):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, TypeField_quotes)
        return _dict


class URLQueryConfiguration:
    def __init__(self,
                 name: str = None,
                 value: str = None
                 ):
        self.name = name
        self.value = value

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, URLQueryConfiguration)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['error'] = self.error.to_dict() if self.error else None
        _dict['file'] = self.file.to_dict() if self.file else None
        _dict['__wg'] = self.__wg.to_dict() if self.__wg else None

        json_parser.recover_dict_keys(_dict, UploadHookPayload)
        return _dict


class UploadHookPayload_error:
    def __init__(self,
                 message: str = None,
                 name: str = None
                 ):
        self.message = message
        self.name = name

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, UploadHookPayload_error)
        return _dict


class UploadHookResponse:
    def __init__(self,
                 error: str = None,
                 fileKey: str = None
                 ):
        self.error = error
        self.fileKey = fileKey

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, UploadHookResponse)
        return _dict


class UploadedFile:
    def __init__(self,
                 key: str = None
                 ):
        self.key = key

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()

        json_parser.recover_dict_keys(_dict, UploadedFile)
        return _dict


class UploadedFiles(list['UploadedFile']):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, UploadedFiles)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['jwtConfig'] = self.jwtConfig.to_dict() if self.jwtConfig else None
        _dict[
            'jwtWithAccessTokenExchangeConfig'] = self.jwtWithAccessTokenExchangeConfig.to_dict() if self.jwtWithAccessTokenExchangeConfig else None
        _dict['kind'] = self.kind.value if self.kind else None

        json_parser.recover_dict_keys(_dict, UpstreamAuthentication)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['customClaims'] = self.customClaims.to_dict() if self.customClaims else None

        json_parser.recover_dict_keys(_dict, User)
        return _dict


class User_customClaims(dict[str, object]):
    def to_dict(self) -> dict:
        _dict = self

        json_parser.recover_dict_keys(_dict, User_customClaims)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['allowedHostNames'] = [x.to_dict() for x in self.allowedHostNames] if self.allowedHostNames else None
        _dict['authenticationConfig'] = self.authenticationConfig.to_dict() if self.authenticationConfig else None
        _dict['corsConfiguration'] = self.corsConfiguration.to_dict() if self.corsConfiguration else None
        _dict['engineConfiguration'] = self.engineConfiguration.to_dict() if self.engineConfiguration else None
        _dict['nodeOptions'] = self.nodeOptions.to_dict() if self.nodeOptions else None
        _dict['operations'] = [x.to_dict() for x in self.operations] if self.operations else None
        _dict['s3UploadConfiguration'] = [x.to_dict() for x in
                                          self.s3UploadConfiguration] if self.s3UploadConfiguration else None
        _dict['serverOptions'] = self.serverOptions.to_dict() if self.serverOptions else None
        _dict['webhooks'] = [x.to_dict() for x in self.webhooks] if self.webhooks else None

        json_parser.recover_dict_keys(_dict, UserDefinedApi)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['variableKind'] = self.variableKind.value if self.variableKind else None
        _dict['dateOffset'] = self.dateOffset.to_dict() if self.dateOffset else None

        json_parser.recover_dict_keys(_dict, VariableInjectionConfiguration)
        return _dict


class VariableWhereInput:
    def __init__(self,
                 filter: 'VariableWhereInputFilter' = None,
                 not_: 'VariableWhereInput' = None
                 ):
        self.filter = json_parser.parse_dict_to_class(filter, VariableWhereInputFilter)
        self.not_ = json_parser.parse_dict_to_class(not_, VariableWhereInput)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['filter'] = self.filter.to_dict() if self.filter else None
        _dict['not_'] = self.not_.to_dict() if self.not_ else None

        json_parser.recover_dict_keys(_dict, VariableWhereInput)
        return _dict


class VariableWhereInputConfiguration:
    def __init__(self,
                 variablePathComponents: list[str] = None,
                 whereInput: 'VariableWhereInput' = None
                 ):
        self.variablePathComponents = variablePathComponents
        self.whereInput = json_parser.parse_dict_to_class(whereInput, VariableWhereInput)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['whereInput'] = self.whereInput.to_dict() if self.whereInput else None

        json_parser.recover_dict_keys(_dict, VariableWhereInputConfiguration)
        return _dict


class VariableWhereInputFilter:
    def __init__(self,
                 field: str = None,
                 relation: 'VariableWhereInputRelationFilter' = None,
                 scalar: 'VariableWhereInputScalarFilter' = None
                 ):
        self.field = field
        self.relation = json_parser.parse_dict_to_class(relation, VariableWhereInputRelationFilter)
        self.scalar = json_parser.parse_dict_to_class(scalar, VariableWhereInputScalarFilter)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['relation'] = self.relation.to_dict() if self.relation else None
        _dict['scalar'] = self.scalar.to_dict() if self.scalar else None

        json_parser.recover_dict_keys(_dict, VariableWhereInputFilter)
        return _dict


class VariableWhereInputRelationFilter:
    def __init__(self,
                 type: VariableWhereInputRelationFilterType = None,
                 where: 'VariableWhereInput' = None
                 ):
        self.type = type
        self.where = json_parser.parse_dict_to_class(where, VariableWhereInput)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['type'] = self.type.value if self.type else None
        _dict['where'] = self.where.to_dict() if self.where else None

        json_parser.recover_dict_keys(_dict, VariableWhereInputRelationFilter)
        return _dict


class VariableWhereInputScalarFilter:
    def __init__(self,
                 insensitive: bool = None,
                 type: VariableWhereInputScalarFilterType = None
                 ):
        self.insensitive = insensitive
        self.type = type

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['type'] = self.type.value if self.type else None

        json_parser.recover_dict_keys(_dict, VariableWhereInputScalarFilter)
        return _dict


class WebhookConfiguration:
    def __init__(self,
                 filePath: str = None,
                 name: str = None,
                 verifier: 'WebhookVerifier' = None
                 ):
        self.filePath = filePath
        self.name = name
        self.verifier = json_parser.parse_dict_to_class(verifier, WebhookVerifier)

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['verifier'] = self.verifier.to_dict() if self.verifier else None

        json_parser.recover_dict_keys(_dict, WebhookConfiguration)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['kind'] = self.kind.value if self.kind else None
        _dict['secret'] = self.secret.to_dict() if self.secret else None

        json_parser.recover_dict_keys(_dict, WebhookVerifier)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['api'] = self.api.to_dict() if self.api else None

        json_parser.recover_dict_keys(_dict, WunderGraphConfiguration)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['headers'] = self.headers.to_dict() if self.headers else None

        json_parser.recover_dict_keys(_dict, WunderGraphRequest)
        return _dict


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

    def to_dict(self) -> dict:
        _dict = self.__dict__.copy()
        _dict['headers'] = self.headers.to_dict() if self.headers else None

        json_parser.recover_dict_keys(_dict, WunderGraphResponse)
        return _dict


def register_init_parameter_renames():
    json_parser.init_parameter_renames[PostResolveGetTransformation] = [
        json_parser.init_parameter_rename('from', 'from_')]
    json_parser.init_parameter_renames[VariableWhereInput] = [json_parser.init_parameter_rename('not', 'not_')]
