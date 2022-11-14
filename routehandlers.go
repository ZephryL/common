package common

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// ------------------------------------------------------------------------------
// On RouteHandler, return a list of routes
// ------------------------------------------------------------------------------
func RouteWalker(s *System, router *mux.Router) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set response header for JSON
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		var vRouteList = new(RouteList)
		if err := router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			// Create a Route, add to RouteList
			var vRoute Route
			pathTemplate, err := route.GetPathTemplate()

			if err == nil {
				vRoute.Path = pathTemplate
			}
			queriesTemplates, err := route.GetQueriesTemplates()
			if err == nil {
				vRoute.Queries = strings.Join(queriesTemplates, ",")
			}
			methods, err := route.GetMethods()
			if err == nil {
				vRoute.Methods = strings.Join(methods, ",")
			}
			// add the latest route, return ok
			vRouteList.List = append(vRouteList.List, vRoute)
			return nil
		}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Walking the router failed: %v", err.Error())))
			return
		}

		// Send results as json
		if err := json.NewEncoder(w).Encode(vRouteList); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Your call was politely taken, but the JSON Encoder failed to format a reply!"))
		}
	}
}
