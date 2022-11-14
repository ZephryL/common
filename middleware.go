package common

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
)

func Cors(s *System, next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS and AUTH headers
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, POST, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		}

		// Get out if it's a pre-flight check
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Chain next
		next.ServeHTTP(w, r)
	})
}

func Auth(s *System, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get out if it's a pre-flight check
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Test if a cookie was received
		cookie, err := r.Cookie("zeph-cookie")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("HTTP %v - Couldn't find me no zeph-cookie: %v", http.StatusUnauthorized, err.Error())))
			return
		}
		// Decode the cookie
		vCookieValue := make(map[string]string)
		err = s.Cookie.Decode("zeph-cookie", cookie.Value, &vCookieValue)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("HTTP %v - Invalid Cookie Value: %v", http.StatusUnauthorized, err.Error())))
			return
		}
		// Get UsrKey and Token from cookie
		var vToken = new(Token)
		vToken.Key, err = strconv.Atoi(vCookieValue["key"])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("HTTP %v - Corrupt Cookie Key", http.StatusUnauthorized)))
			return
		}
		vToken.Token = vCookieValue["token"]
		// Authenticate user token
		if err = Authenticate(s, vToken); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("HTTP %v - Could Not Athenticate: %v", http.StatusUnauthorized, err.Error())))
			return
		}
		// Store Usr_Key in Session
		s.Usr_Key = vToken.Key
		// Only do this if required
		// Authorize user access to route
		// var vRoute string = r.RequestURI;
		// var vMethod string = r.Method;
		// if err = Authorize(s, vRoute, vMethod); err != nil {
		// 	w.WriteHeader(http.StatusForbidden);
		// 	w.Write([]byte(fmt.Sprintf("HTTP %v - %v", http.StatusForbidden, err.Error())));
		// 	return;
		// }

		// User is authentic and authorized - Rewrite cookie defaults, set response cookie
		SetCookieDefaults(cookie)
		http.SetCookie(w, cookie)

		// Set request context, and handle next
		ctx := r.Context()
		ctx = context.WithValue(ctx, "usrkey", vToken.Key)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	}
}

func AuthOnly(s *System, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get out if it's a pre-flight check
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Test if a cookie was received
		cookie, err := r.Cookie("zeph-cookie")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("HTTP %v - Couldn't find me no zeph-cookie: %v", http.StatusUnauthorized, err.Error())))
			return
		}
		// Decode the cookie
		vCookieValue := make(map[string]string)
		err = s.Cookie.Decode("zeph-cookie", cookie.Value, &vCookieValue)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("HTTP %v - Invalid Cookie Value: %v", http.StatusUnauthorized, err.Error())))
			return
		}
		// Get UsrKey and Token from cookie
		var vToken = new(Token)
		vToken.Key, err = strconv.Atoi(vCookieValue["key"])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("HTTP %v - Corrupt Cookie Key", http.StatusUnauthorized)))
			return
		}
		vToken.Token = vCookieValue["token"]
		// Authenticate user token
		if err = Authenticate(s, vToken); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("HTTP %v - Could Not Athenticate: %v", http.StatusUnauthorized, err.Error())))
			return
		}
		// Store Usr_Key in Session
		s.Usr_Key = vToken.Key

		// User is authentic and authorized - Rewrite cookie defaults, set response cookie
		SetCookieDefaults(cookie)
		http.SetCookie(w, cookie)

		// Set request context, and handle next
		ctx := r.Context()
		ctx = context.WithValue(ctx, "usrkey", vToken.Key)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	}
}

func SetCookieDefaults(cookie *http.Cookie) {
	cookie.MaxAge = 86400 * 30 // seconds in a day times 30 days - roughly one month
	cookie.Secure = true
	cookie.HttpOnly = true
	cookie.SameSite = http.SameSiteNoneMode
	cookie.Path = "/"
}
