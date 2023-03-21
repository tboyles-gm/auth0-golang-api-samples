package router

import (
	"01-Authorization-RS256/middleware"
	"github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"net/http"
	"os"
	"context"
	"log"
	flagsmith "github.com/Flagsmith/flagsmith-go-client/v2"
)

// New sets up our routes and returns a *http.ServeMux.
func New() *http.ServeMux {
		
	router := http.NewServeMux()

	// This route is always accessible.
	router.Handle("/api/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client := flagsmith.NewClient(os.Getenv("FLAGSMITH_SDK_KEY"), flagsmith.WithContext(ctx))
		flags, _ := client.GetEnvironmentFlags()
		showFeature,err := flags.IsFeatureEnabled("test")
		if err != nil {
			log.Println("Error retrieving feature flag")
		}
		log.Println(showFeature)
		if showFeature {
    		w.Write([]byte(`{"message":"Hello from a public endpoint! You don't need to be authenticated to see this. This is the Flagsmith version. The feature is on."}`))
		} else {
	    	w.Write([]byte(`{"message":"Hello from a public endpoint! You don't need to be authenticated to see this. This is the Flagsmith version. The feature is off."}`))
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
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := flagsmith.NewClient(os.Getenv("FLAGSMITH_SDK_KEY"), flagsmith.WithContext(ctx))
			flags, _ := client.GetEnvironmentFlags()
			showFeature,err := flags.IsFeatureEnabled("test")
			if err != nil {
				log.Println("Error retrieving feature flag")
			}
			log.Println(showFeature)
			if showFeature {
				w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this. This is the Flagsmith version. The feature is on."}`))
			} else {
				w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this. This is the Flagsmith version. The feature is off."}`))
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
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := flagsmith.NewClient(os.Getenv("FLAGSMITH_SDK_KEY"), flagsmith.WithContext(ctx))
			flags, _ := client.GetEnvironmentFlags()
			showFeature,err := flags.IsFeatureEnabled("test")
			if err != nil {
				log.Println("Error retrieving feature flag")
			}
			log.Println(showFeature)
			if showFeature {
				w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this. This is the Flagsmith version. The feature is on."}`))
			} else {
				w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this. This is the Flagsmith version. The feature is off."}`))
			}
		}),
	))

	return router
}
