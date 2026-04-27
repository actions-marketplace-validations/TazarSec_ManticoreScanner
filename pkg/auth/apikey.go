package auth

import "context"

type APIKeyAuthenticator struct {
	key string
}

func NewAPIKeyAuthenticator(key string) *APIKeyAuthenticator {
	return &APIKeyAuthenticator{key: key}
}

func (a *APIKeyAuthenticator) AuthorizationHeader(_ context.Context) (string, error) {
	return "Bearer " + a.key, nil
}
