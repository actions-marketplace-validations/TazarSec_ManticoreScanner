package auth

import "context"

const (
	ModeAPIKey     = "api-key"
	ModeGitHubOIDC = "github-oidc"

	// GitHubOIDCAudience is the JWT audience the backend requires for
	// GitHub-issued OIDC tokens. The CLI never accepts this from user
	// input — minting a token for a different audience is always wrong.
	GitHubOIDCAudience = "tazarsec.dev"
)

// Authenticator produces the value for the Authorization header on
// outgoing requests to the Manticore backend.
type Authenticator interface {
	AuthorizationHeader(ctx context.Context) (string, error)
}
