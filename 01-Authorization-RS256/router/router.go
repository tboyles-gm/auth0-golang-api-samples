package router

import (
	"01-Authorization-RS256/middleware"
	"github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"net/http"
	"os"
	"time"
	"fmt"
	"encoding/json"
	"log"
	"github.com/growthbook/growthbook-golang"
)

type GBFeaturesResponse struct {
	Status      int             `json:"status"`
	Features    json.RawMessage `json:"features"`
	DateUpdated time.Time       `json:"dateUpdated"`
}

func GetFeatureFlag(flagname string) (state bool) {

	log.Println("Getting state for flag ", flagname)
	userAttributes := growthbook.Attributes{
		"id":       "auth0-golang-api-samples",
		"service": true,
		"country":  "United States",
	}

	// Get JSON from GrowthBook and deserialize it into GBFeaturesResponse struct
	res, err := http.Get(os.Getenv("GROWTHBOOK_URL"))
	if err != nil {
		fmt.Printf("Error fetching features from GrowthBook: %s \n", err)
		os.Exit(1)
	}
	var featuresResponse GBFeaturesResponse
	err = json.NewDecoder(res.Body).Decode(&featuresResponse)
	if err != nil {
		fmt.Printf("Error decoding JSON: %s \n", err)
		os.Exit(1)
	}
	features := growthbook.ParseFeatureMap(featuresResponse.Features)

	// This will get called when the font_colour experiment below is evaluated
	trackingCallback := func(experiment *growthbook.Experiment, result *growthbook.ExperimentResult) {
		fmt.Printf("Experiment Viewed: %s - Variation index: %d - Value: %s \n", experiment.Key, result.VariationID, result.Value)
	}

	// Create a growthbook.Context instance with the features and attributes
	context := growthbook.NewContext().
		WithFeatures(features).
		WithAttributes(userAttributes).
		WithTrackingCallback(trackingCallback)

	// Create a growthbook.GrowthBook instance
	gb := growthbook.New(context)

	result := gb.Feature(flagname)
	log.Println("Result was ", result.Value)
	if result.On {
		return true
	} else {
		return false
	}
}


// New sets up our routes and returns a *http.ServeMux.
func New() *http.ServeMux {

	

	router := http.NewServeMux()

	// This route is always accessible.
	router.Handle("/api/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if GetFeatureFlag("test") {
    			w.Write([]byte(`{"message":"Hello from a public endpoint! You don't need to be authenticated to see this. This is the Launchdarkly version. The feature is on."}`))
		} else {
	    		w.Write([]byte(`{"message":"Hello from a public endpoint! You don't need to be authenticated to see this. This is the Launchdarkly version. The feature is off."}`))
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
			if GetFeatureFlag("test") {
				w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this. This is the Launchdarkly version. The feature is on."}`))
			} else {
				w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this. This is the Launchdarkly version. The feature is off."}`))
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
			if GetFeatureFlag("test") {
				w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this. This is the Launchdarkly version. The feature is on."}`))
			} else {
				w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this. This is the Launchdarkly version. The feature is off."}`))
			}
		}),
	))

	return router
}
