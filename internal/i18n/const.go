package i18n

// Common errors
var (
	ErrNotFound       = NewErrorWithCode("ErrorResourceNotFound", ErrorNotFound)
	ErrUnauthorized   = NewErrorWithCode("ErrorUnauthorized", ErrorUnauthorized)
	ErrForbidden      = NewErrorWithCode("ErrorForbidden", ErrorForbidden)
	ErrBadRequest     = NewErrorWithCode("ErrorBadRequest", ErrorBadRequest)
	ErrInternalServer = NewErrorWithCode("ErrorInternalServer", ErrorInternalServer)
)

// Tenant related errors
var (
	ErrorTenantNotFound        = NewErrorWithCode("ErrorTenantNotFound", ErrorNotFound)
	ErrorTenantNameRequired    = NewErrorWithCode("ErrorTenantNameRequired", ErrorBadRequest)
	ErrorTenantPrefixExists    = NewErrorWithCode("ErrorTenantPrefixExists", ErrorConflict)
	ErrorTenantNameExists      = NewErrorWithCode("ErrorTenantNameExists", ErrorConflict)
	ErrorTenantRequiredFields  = NewErrorWithCode("ErrorTenantRequiredFields", ErrorBadRequest)
	ErrorTenantPermissionError = NewErrorWithCode("ErrorTenantPermissionError", ErrorForbidden)
	ErrorTenantDisabled        = NewErrorWithCode("ErrorTenantDisabled", ErrorForbidden)
)

// User related errors
var (
	ErrorUserNotFound             = NewErrorWithCode("ErrorUserNotFound", ErrorNotFound)
	ErrorInvalidCredentials       = NewErrorWithCode("ErrorInvalidCredentials", ErrorUnauthorized)
	ErrorUserDisabled             = NewErrorWithCode("ErrorUserDisabled", ErrorForbidden)
	ErrorUserNamePasswordRequired = NewErrorWithCode("ErrorUserNamePasswordRequired", ErrorBadRequest)
	ErrorInvalidOldPassword       = NewErrorWithCode("ErrorInvalidOldPassword", ErrorForbidden)
	ErrorUsernameExists           = NewErrorWithCode("ErrorUsernameExists", ErrorConflict)
	ErrorInvalidUsername          = NewErrorWithCode("ErrorInvalidUsername", ErrorBadRequest)
	ErrorEmailExists              = NewErrorWithCode("ErrorEmailExists", ErrorConflict)
	ErrorInvalidEmail             = NewErrorWithCode("ErrorInvalidEmail", ErrorBadRequest)
)

// MCP related errors
var (
	ErrorMCPServerNotFound     = NewErrorWithCode("ErrorMCPServerNotFound", ErrorNotFound)
	ErrorMCPServerExists       = NewErrorWithCode("ErrorMCPServerExists", ErrorConflict)
	ErrorMCPServerValidation   = NewErrorWithCode("ErrorMCPServerValidation", ErrorBadRequest)
	ErrorTenantRequired        = NewErrorWithCode("ErrorTenantRequired", ErrorBadRequest)
	ErrorMCPServerNameRequired = NewErrorWithCode("ErrorMCPServerNameRequired", ErrorBadRequest)
	ErrorVersionRequired       = NewErrorWithCode("ErrorVersionRequired", ErrorBadRequest)
	ErrorRouterPrefixError     = NewErrorWithCode("ErrorRouterPrefixError", ErrorBadRequest)
	ErrorMCPConfigInvalid      = NewErrorWithCode("ErrorMCPConfigInvalid", ErrorBadRequest)
	ErrorMCPRequestFailed      = NewErrorWithCode("ErrorMCPRequestFailed", ErrorInternalServer)
)

// API related errors
var (
	ErrorAPINotFound             = NewErrorWithCode("ErrorAPINotFound", ErrorNotFound)
	ErrorAPIMethodNotAllowed     = NewErrorWithCode("ErrorAPIMethodNotAllowed", ErrorMethodNotAllowed)
	ErrorAPIRateLimitExceeded    = NewErrorWithCode("ErrorAPIRateLimitExceeded", ErrorTooManyRequests)
	ErrorAPIUnavailable          = NewErrorWithCode("ErrorAPIUnavailable", ErrorServiceUnavailable)
	ErrorAPITimeout              = NewErrorWithCode("ErrorAPITimeout", ErrorGatewayTimeout)
	ErrorAPIValidationFailed     = NewErrorWithCode("ErrorAPIValidationFailed", ErrorBadRequest)
	ErrorAPIMalformedRequest     = NewErrorWithCode("ErrorAPIMalformedRequest", ErrorBadRequest)
	ErrorAPIResponseInvalid      = NewErrorWithCode("ErrorAPIResponseInvalid", ErrorInternalServer)
	ErrorAPIInvalidCredentials   = NewErrorWithCode("ErrorAPIInvalidCredentials", ErrorUnauthorized)
	ErrorAPIPermissionDenied     = NewErrorWithCode("ErrorAPIPermissionDenied", ErrorForbidden)
	ErrorAPIUnsupportedMediaType = NewErrorWithCode("ErrorAPIUnsupportedMediaType", ErrorUnsupportedMedia)
)

// General validation errors
var (
	ErrorRequiredField          = NewErrorWithCode("ErrorRequiredField", ErrorBadRequest)
	ErrorInvalidFormat          = NewErrorWithCode("ErrorInvalidFormat", ErrorBadRequest)
	ErrorInvalidValue           = NewErrorWithCode("ErrorInvalidValue", ErrorBadRequest)
	ErrorDuplicateEntity        = NewErrorWithCode("ErrorDuplicateEntity", ErrorConflict)
	ErrorDataIntegrityViolation = NewErrorWithCode("ErrorDataIntegrityViolation", ErrorBadRequest)
)

// Tenant related success messages
const (
	SuccessTenantCreated = "SuccessTenantCreated"
	SuccessTenantUpdated = "SuccessTenantUpdated"
	SuccessTenantDeleted = "SuccessTenantDeleted"
	SuccessTenantInfo    = "SuccessTenantInfo"
	SuccessTenantList    = "SuccessTenantList"
	SuccessTenantStatus  = "SuccessTenantStatus"
)

// User related success messages
const (
	SuccessLogin              = "SuccessLogin"
	SuccessLogout             = "SuccessLogout"
	SuccessPasswordChanged    = "SuccessPasswordChanged"
	SuccessUserCreated        = "SuccessUserCreated"
	SuccessUserUpdated        = "SuccessUserUpdated"
	SuccessUserDeleted        = "SuccessUserDeleted"
	SuccessUserInfo           = "SuccessUserInfo"
	SuccessUserList           = "SuccessUserList"
	SuccessUserWithTenants    = "SuccessUserWithTenants"
	SuccessUserTenantsUpdated = "SuccessUserTenantsUpdated"
)

// MCP related success messages
const (
	SuccessMCPServerCreated  = "SuccessMCPServerCreated"
	SuccessMCPServerUpdated  = "SuccessMCPServerUpdated"
	SuccessMCPServerDeleted  = "SuccessMCPServerDeleted"
	SuccessMCPServerSynced   = "SuccessMCPServerSynced"
	SuccessMCPServerList     = "SuccessMCPServerList"
	SuccessMCPServerInfo     = "SuccessMCPServerInfo"
	SuccessMCPServerStatus   = "SuccessMCPServerStatus"
	SuccessMCPConfigVersions = "SuccessMCPConfigVersions"
	SuccessMCPCapabilities   = "SuccessMCPCapabilities"
)

// OpenAPI related success messages
const (
	SuccessOpenAPIImported  = "SuccessOpenAPIImported"
	SuccessOpenAPIExported  = "SuccessOpenAPIExported"
	SuccessOpenAPIValidated = "SuccessOpenAPIValidated"
)

// API related success messages
const (
	SuccessAPICreated      = "SuccessAPICreated"
	SuccessAPIUpdated      = "SuccessAPIUpdated"
	SuccessAPIDeleted      = "SuccessAPIDeleted"
	SuccessAPIList         = "SuccessAPIList"
	SuccessAPIInfo         = "SuccessAPIInfo"
	SuccessAPIKeyCreated   = "SuccessAPIKeyCreated"
	SuccessAPIKeyRevoked   = "SuccessAPIKeyRevoked"
	SuccessAPIKeyList      = "SuccessAPIKeyList"
	SuccessAPIRouteCreated = "SuccessAPIRouteCreated"
	SuccessAPIRouteUpdated = "SuccessAPIRouteUpdated"
	SuccessAPIRouteDeleted = "SuccessAPIRouteDeleted"
	SuccessAPIRouteList    = "SuccessAPIRouteList"
)

// Chat related success messages
const (
	SuccessChatSessions     = "SuccessChatSessions"
	SuccessChatMessages     = "SuccessChatMessages"
	SuccessChatMessageSaved = "SuccessChatMessageSaved"
	SuccessChatCreated      = "SuccessChatCreated"
	SuccessChatUpdated      = "SuccessChatUpdated"
	SuccessChatDeleted      = "SuccessChatDeleted"
	SuccessChatHistory      = "SuccessChatHistory"
)

// General success messages
const (
	SuccessOperationCompleted = "SuccessOperationCompleted"
	SuccessItemCreated        = "SuccessItemCreated"
	SuccessItemUpdated        = "SuccessItemUpdated"
	SuccessItemDeleted        = "SuccessItemDeleted"
	SuccessDataExported       = "SuccessDataExported"
	SuccessDataImported       = "SuccessDataImported"
	SuccessDataSaved          = "SuccessDataSaved"
)
