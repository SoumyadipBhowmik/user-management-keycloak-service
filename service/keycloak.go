package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type KeycloakClient struct {
	BaseURL       string
	Realm         string
	ClientID      string
	ClientSecret  string
	AdminUsername string
	AdminPassword string
	HTTPClient    *http.Client
}

type KeycloakTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type KeycloakUserInfo struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
}

type KeycloakCreateUserRequest struct {
	Username    string               `json:"username"`
	Email       string               `json:"email"`
	FirstName   string               `json:"firstName"`
	LastName    string               `json:"lastName"`
	Enabled     bool                 `json:"enabled"`
	Credentials []KeycloakCredential `json:"credentials,omitempty"`
}

type KeycloakCredential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

func NewKeycloakClient() *KeycloakClient {
	return &KeycloakClient{
		BaseURL:       os.Getenv("KEYCLOAK_URL"),
		Realm:         os.Getenv("KEYCLOAK_REALM"),
		ClientID:      os.Getenv("KEYCLOAK_CLIENT_ID"),
		ClientSecret:  os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		AdminUsername: os.Getenv("KEYCLOAK_ADMIN_USERNAME"),
		AdminPassword: os.Getenv("KEYCLOAK_ADMIN_PASSWORD"),
		HTTPClient:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Login validates user credentials with Keycloak and returns token
func (kc *KeycloakClient) Login(username, password string) (*KeycloakTokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", kc.BaseURL, kc.Realm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", kc.ClientID)
	data.Set("client_secret", kc.ClientSecret)
	data.Set("username", username)
	data.Set("password", password)
	data.Set("scope", "openid profile email") // Add required scopes

	logrus.Debugf("Attempting login for user: %s", username)
	logrus.Debugf("Token URL: %s", tokenURL)
	logrus.Debugf("Client ID: %s", kc.ClientID)
	logrus.Debugf("Client Secret length: %d", len(kc.ClientSecret))

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute login request: %w", err)
	}
	defer resp.Body.Close()

	// Log response details for debugging
	logrus.Debugf("Login response status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		// Read response body for more details
		body := make([]byte, 1024)
		resp.Body.Read(body)
		logrus.Errorf("Login failed with status: %d, body: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("login failed with status: %d", resp.StatusCode)
	}

	var tokenResp KeycloakTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// ValidateToken validates access token and returns user info
func (kc *KeycloakClient) ValidateToken(accessToken string) (*KeycloakUserInfo, error) {
	userInfoURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", kc.BaseURL, kc.Realm)

	logrus.Debugf("Validating token at URL: %s", userInfoURL)
	logrus.Debugf("Token length: %d", len(accessToken))
	logrus.Debugf("Token starts with: %s...", accessToken[:min(20, len(accessToken))])

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute userinfo request: %w", err)
	}
	defer resp.Body.Close()

	logrus.Debugf("Token validation response status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		// Read response body for debugging
		body := make([]byte, 1024)
		resp.Body.Read(body)
		logrus.Errorf("Token validation failed with status: %d, body: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("token validation failed with status: %d", resp.StatusCode)
	}

	var userInfo KeycloakUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	return &userInfo, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetAdminToken gets admin access token for administrative operations
func (kc *KeycloakClient) GetAdminToken() (string, error) {
	tokenURL := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", kc.BaseURL)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", "admin-cli")
	data.Set("username", kc.AdminUsername)
	data.Set("password", kc.AdminPassword)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create admin token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute admin token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("admin token request failed with status: %d", resp.StatusCode)
	}

	var tokenResp KeycloakTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode admin token response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// CreateUser creates a new user in Keycloak
func (kc *KeycloakClient) CreateUser(username, email, firstName, lastName, password string) (string, error) {
	adminToken, err := kc.GetAdminToken()
	if err != nil {
		return "", fmt.Errorf("failed to get admin token: %w", err)
	}

	createUserURL := fmt.Sprintf("%s/admin/realms/%s/users", kc.BaseURL, kc.Realm)

	userReq := KeycloakCreateUserRequest{
		Username:  username,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Enabled:   true,
		Credentials: []KeycloakCredential{
			{
				Type:      "password",
				Value:     password,
				Temporary: false,
			},
		},
	}

	jsonData, err := json.Marshal(userReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal user request: %w", err)
	}

	req, err := http.NewRequest("POST", createUserURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create user request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute create user request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create user failed with status: %d", resp.StatusCode)
	}

	// Extract user ID from Location header
	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("no location header in create user response")
	}

	parts := strings.Split(location, "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid location header format")
	}

	userID := parts[len(parts)-1]
	logrus.Debugf("Created Keycloak user with ID: %s", userID)

	return userID, nil
}
