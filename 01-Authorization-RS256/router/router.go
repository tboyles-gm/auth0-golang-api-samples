package router

import (
	"01-Authorization-RS256/middleware"
	"github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"net/http"
	"os"
	"time"
	ld "github.com/launchdarkly/go-server-sdk/v6"
    "github.com/launchdarkly/go-sdk-common/v3/ldcontext"
)

// New sets up our routes and returns a *http.ServeMux.
func New() *http.ServeMux {
	
	client, _ := ld.MakeClient(os.Getenv("LD_SDK_KEY"), 5 * time.Second)
	flagKey := "test"
	context := ldcontext.NewBuilder("api_public").
    	Name("api_public").
    	Build()

	
	router := http.NewServeMux()

	// This route is always accessible.
	router.Handle("/api/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		showFeature, _ := client.BoolVariation(flagKey, context, false)
		if showFeature {
    		w.Write([]byte(`{"message":"Hello from a public endpoint! You don't need to be authenticated to see this. The feature is on."}`))
		} else {
    		w.Write([]byte(`{"message":"Hello from a public endpoint! You don't need to be authenticated to see this. The feature is off."}`))
		}
		
	}))

	// This route is only accessible if the user has a valid access_token.
	router.Handle("/api/private", middleware.EnsureValidToken()(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS Headers.
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			showFeature, _ := client.BoolVariation(flagKey, context, false)
			if showFeature {
				w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this. The feature is on."}`))
			} else {
				w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this. The feature is off."}`))
			}
		}),
	))

	// This route is only accessible if the user has a
	// valid access_token with the read:messages scope.
	router.Handle("/api/private-scoped", middleware.EnsureValidToken()(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS Headers.
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")

			w.Header().Set("Content-Type", "application/json")

			token := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)

			claims := token.CustomClaims.(*middleware.CustomClaims)
			if !claims.HasScope("read:messages") {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"message":"Insufficient scope."}`))
				return
			}

			w.WriteHeader(http.StatusOK)
			showFeature, _ := client.BoolVariation(flagKey, context, false)
			if showFeature {
				w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this. The feature is on."}`))
			} else {
				w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this. The feature is off."}`))
			}
		}),
	))

	return router
}
