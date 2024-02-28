package aws_signing_helper

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
)

const DefaultPort = 9911
const LocalHostAddress = "127.0.0.1"

var RefreshTime = time.Minute * time.Duration(5)

type RefreshableCred struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Code            string
	Type            string
	Expiration      time.Time
	LastUpdated     time.Time
}

type Endpoint struct {
	Host    string
	PortNum int
	Server  *http.Server
	TmpCred RefreshableCred
}

type SessionToken struct {
	Expiration time.Time
}

const TOKEN_RESOURCE_PATH = "/latest/api/token"
const SECURITY_CREDENTIALS_RESOURCE_PATH = "/latest/meta-data/iam/security-credentials/"

const EC2_METADATA_TOKEN_HEADER = "x-aws-ec2-metadata-token"
const EC2_METADATA_TOKEN_TTL_HEADER = "x-aws-ec2-metadata-token-ttl-seconds"
const MAX_TOKEN_TTL_SECONDS = 21600
const DEFAULT_TOKEN_TTL_SECONDS = MAX_TOKEN_TTL_SECONDS

const X_FORWARDED_FOR_HEADER = "X-Forwarded-For"

const REFRESHABLE_CRED_TYPE = "AWS-HMAC"
const REFRESHABLE_CRED_CODE = "Success"

const MAX_TOKENS = 256

var tokenStorageMutex sync.Mutex
var tokenMap = make(map[string]time.Time)
var credMutex sync.Mutex

// GenerateToken - Generates a random string with the specified length
func GenerateToken(length int) (string, error) {
	if length < 0 || length >= 128 {
		msg := "invalid token length"
		return "", errors.New(msg)
	}
	randomBytes := make([]byte, 128)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(randomBytes)[:length], nil
}

// InsertToken - Removes the token that expires the earliest
func InsertToken(token string, expirationTime time.Time) error {
	tokenStorageMutex.Lock()
	if len(tokenMap) == MAX_TOKENS {
		earliestExpirationTime := time.Unix(1<<63-1, 0)
		var earliestExpiringToken string
		for key, value := range tokenMap {
			if earliestExpirationTime.After(value) {
				earliestExpiringToken = key
				earliestExpirationTime = value
			}
		}

		delete(tokenMap, earliestExpiringToken)
		log.Printf("evicting earliest expiring token: %s", earliestExpiringToken)
	}
	tokenMap[token] = expirationTime
	tokenStorageMutex.Unlock()
	return nil
}

// CheckValidToken - Helper function that checks to see whether the token provided in the request is valid
func CheckValidToken(w http.ResponseWriter, r *http.Request) error {
	token := r.Header.Get(EC2_METADATA_TOKEN_HEADER)
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		msg := "no token provided"

		log.WithFields(log.Fields{
			"status": http.StatusUnauthorized,
		}).Warn(msg)

		_, _ = io.WriteString(w, msg)
		return errors.New(msg)
	}

	tokenStorageMutex.Lock()
	expiration, ok := tokenMap[token]
	tokenStorageMutex.Unlock()
	if ok {
		if time.Now().After(expiration) {
			w.WriteHeader(http.StatusUnauthorized)
			msg := "invalid token provided"

			log.WithFields(log.Fields{
				"status": http.StatusUnauthorized,
			}).Warn(msg)

			_, _ = io.WriteString(w, msg)
			return errors.New(msg)
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		msg := "invalid token provided"

		log.WithFields(log.Fields{
			"status": http.StatusUnauthorized,
		}).Warn(msg)

		_, _ = io.WriteString(w, msg)
		return errors.New(msg)
	}

	return nil
}

// FindTokenTTLSeconds - Helper function that finds a token's TTL in seconds
func FindTokenTTLSeconds(r *http.Request) (string, error) {
	token := r.Header.Get(EC2_METADATA_TOKEN_HEADER)
	if token == "" {
		msg := "no token provided"
		return "", errors.New(msg)
	}

	tokenStorageMutex.Lock()
	expiration, ok := tokenMap[token]
	tokenStorageMutex.Unlock()
	if ok {
		tokenTTLFloat := expiration.Sub(time.Now()).Seconds()
		tokenTTLInt64 := int64(tokenTTLFloat)
		return strconv.FormatInt(tokenTTLInt64, 10), nil
	} else {
		msg := "invalid token provided"
		return "", errors.New(msg)
	}
}

func AllIssuesHandlers(cred *RefreshableCred, roleName string, opts *CredentialsOpts, signer Signer, signatureAlgorithm string) (http.HandlerFunc, http.HandlerFunc, http.HandlerFunc) {
	// Handles PUT requests to /latest/api/token/
	putTokenHandler := func(w http.ResponseWriter, r *http.Request) {

		_log := log.WithFields(log.Fields{
			"method":   r.Method,
			"endpoint": "put_token",
		})

		if r.Method != "PUT" {

			_log.WithFields(log.Fields{
				"status": http.StatusMethodNotAllowed,
			}).Warn("method is not supported")

			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Check for the presence of the X-Forwarded-For header
		xForwardedForHeader := r.Header.Get(X_FORWARDED_FOR_HEADER) // canonicalized headers are used (casing doesn't matter)
		if xForwardedForHeader != "" {

			_log.WithFields(log.Fields{
				"status": http.StatusBadRequest,
			}).Warn("unable to process requests with X-Forwarded-For header")

			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "unable to process requests with X-Forwarded-For header")
			return
		}

		// Obtain the token TTL
		tokenTTLStr := r.Header.Get(EC2_METADATA_TOKEN_TTL_HEADER)
		if tokenTTLStr == "" {
			tokenTTLStr = strconv.Itoa(DEFAULT_TOKEN_TTL_SECONDS)
		}
		tokenTTL, err := strconv.Atoi(tokenTTLStr)
		if err != nil || tokenTTL < 1 || tokenTTL > MAX_TOKEN_TTL_SECONDS {

			_log.WithFields(log.Fields{
				"status": http.StatusBadRequest,
			}).Warn("invalid token ttl")

			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "invalid token TTL")
			return
		}

		// Generate token and insert it into map
		token, err := GenerateToken(100)
		if err != nil {

			_log.WithFields(log.Fields{
				"status": http.StatusInternalServerError,
			}).Warn("unable to generate token")

			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "unable to generate token")
			return
		}
		expirationTime := time.Now().Add(time.Second * time.Duration(tokenTTL))
		_ = InsertToken(token, expirationTime)

		w.Header().Set(EC2_METADATA_TOKEN_TTL_HEADER, tokenTTLStr)
		_, _ = io.WriteString(w, token) // nosemgrep

		_log.WithFields(log.Fields{
			"status": http.StatusOK,
		}).Info("token has been generated successfully")
	}

	// Handles requests to /latest/meta-data/iam/security-credentials/
	getRoleNameHandler := func(w http.ResponseWriter, r *http.Request) {

		_log := log.WithFields(log.Fields{
			"method":   r.Method,
			"endpoint": "get_role_name_handler",
		})

		if r.Method != "GET" {

			_log.WithFields(log.Fields{
				"status": http.StatusMethodNotAllowed,
			}).Warn("method is not supported")

			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		err := CheckValidToken(w, r)
		if err != nil {
			return
		}

		tokenTTL, err := FindTokenTTLSeconds(r)
		if err != nil {

			_log.WithError(err).WithFields(log.Fields{
				"status": http.StatusUnauthorized,
			}).Warn("token is not found or expired")

			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set(EC2_METADATA_TOKEN_TTL_HEADER, tokenTTL)
		_, _ = io.WriteString(w, roleName) // nosemgrep
	}

	// Handles GET requests to /latest/meta-data/iam/security-credentials/<ROLE_NAME>
	getCredentialsHandler := func(w http.ResponseWriter, r *http.Request) {

		_log := log.WithFields(log.Fields{
			"method":   r.Method,
			"endpoint": "get_credentials_handler",
		})

		if r.Method != "GET" {

			_log.WithFields(log.Fields{
				"status": http.StatusMethodNotAllowed,
			}).Warn("method is not supported")

			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		err := CheckValidToken(w, r)
		if err != nil {
			return
		}

		credMutex.Lock()
		var nextRefreshTime = cred.Expiration.Add(-RefreshTime)
		if time.Until(nextRefreshTime) < RefreshTime {
			credentialProcessOutput, _ := GenerateCredentials(opts, signer, signatureAlgorithm)
			cred.AccessKeyId = credentialProcessOutput.AccessKeyId
			cred.SecretAccessKey = credentialProcessOutput.SecretAccessKey
			cred.Token = credentialProcessOutput.SessionToken
			cred.Expiration, err = time.Parse(time.RFC3339, credentialProcessOutput.Expiration)
			if err != nil {
				credMutex.Unlock()
				_log.WithError(err).WithFields(log.Fields{
					"format": "RFC3339",
					"value":  credentialProcessOutput.Expiration,
					"status": http.StatusInternalServerError,
				}).Error("cannot parse expiration date")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			cred.Code = REFRESHABLE_CRED_CODE
			cred.LastUpdated = time.Now()
			cred.Type = REFRESHABLE_CRED_TYPE
		}
		credMutex.Unlock()

		err = json.NewEncoder(w).Encode(cred)
		if err != nil {

			_log.WithError(err).WithFields(log.Fields{
				"status": http.StatusInternalServerError,
			}).Warn("failed to encode credentials")

			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "failed to encode credentials")
			return
		}

		tokenTTL, err := FindTokenTTLSeconds(r)
		if err != nil {

			_log.WithError(err).WithFields(log.Fields{
				"status": http.StatusUnauthorized,
			}).Warn("token is not found or expired")

			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set(EC2_METADATA_TOKEN_TTL_HEADER, tokenTTL)
	}

	return putTokenHandler, getRoleNameHandler, getCredentialsHandler
}

func Serve(ctx context.Context, host string, port int, credentialsOptions CredentialsOpts) {
	var refreshableCred = RefreshableCred{}

	roleArn, err := arn.Parse(credentialsOptions.RoleArn)
	if err != nil {
		log.Println("invalid role ARN")
		os.Exit(1)
	}

	signer, signatureAlgorithm, err := GetSigner(&credentialsOptions)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer signer.Close()

	credentialProcessOutput, _ := GenerateCredentials(&credentialsOptions, signer, signatureAlgorithm)
	refreshableCred.AccessKeyId = credentialProcessOutput.AccessKeyId
	refreshableCred.SecretAccessKey = credentialProcessOutput.SecretAccessKey
	refreshableCred.Token = credentialProcessOutput.SessionToken
	refreshableCred.Expiration, _ = time.Parse(time.RFC3339, credentialProcessOutput.Expiration)
	refreshableCred.Code = REFRESHABLE_CRED_CODE
	refreshableCred.LastUpdated = time.Now()
	refreshableCred.Type = REFRESHABLE_CRED_TYPE
	endpoint := &Endpoint{PortNum: port, TmpCred: refreshableCred}
	endpoint.Server = &http.Server{}
	roleResourceParts := strings.Split(roleArn.Resource, "/")
	roleName := roleResourceParts[len(roleResourceParts)-1] // Find role name without path
	putTokenHandler, getRoleNameHandler, getCredentialsHandler := AllIssuesHandlers(&endpoint.TmpCred, roleName, &credentialsOptions, signer, signatureAlgorithm)

	http.HandleFunc("/health", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})

	http.Handle(`/metrics`, promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			ErrorLog:           log.StandardLogger(),
			Registry:           prometheus.DefaultRegisterer,
			DisableCompression: false,
			EnableOpenMetrics:  false,
		}))

	http.HandleFunc(TOKEN_RESOURCE_PATH, putTokenHandler)
	http.HandleFunc(SECURITY_CREDENTIALS_RESOURCE_PATH, getRoleNameHandler)
	http.HandleFunc(SECURITY_CREDENTIALS_RESOURCE_PATH+roleName, getCredentialsHandler)

	// Background thread that cleans up expired tokens
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	go func() {
		flush := func() {
			tokenStorageMutex.Lock()
			defer tokenStorageMutex.Unlock()
			curTime := time.Now()
			for key, value := range tokenMap {
				if curTime.After(value) {
					delete(tokenMap, key)
					log.Printf("removed expired token: %s", key)
				}
			}
		}
		for {
			select {
			case <-ticker.C:
				flush()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Start the credentials endpoint
	addr := fmt.Sprintf("%s:%d", host, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("failed to create listener")
	}

	log.Println("Local server started on port:", port)
	log.Println("Make it available to the sdk by running:")
	log.Printf("export AWS_EC2_METADATA_SERVICE_ENDPOINT=http://%s/", addr)

	go func() {
		if err := endpoint.Server.Serve(listener); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				log.Fatal("Httpserver: ListenAndServe() error")
			}
		}
	}()

	<-ctx.Done()

	if err := endpoint.Server.Close(); err != nil {
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal("Httpserver: ListenAndServe() error")
		}
	}
}
