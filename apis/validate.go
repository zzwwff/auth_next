package apis

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/opentreehole/go-common"

	. "auth_next/models"
)

// ValidateUserToken
//
//	@Summary		Validate a user token
//	@Description	Validate a user JWT token from Authorization header and return user data
//	@Tags			validate
//	@Produce		json
//	@Router			/validate/user [post]
//	@Success		200	{object}	ValidateUserResponse
//	@Failure		401	{object}	common.MessageResponse
func ValidateUserToken(c *fiber.Ctx) error {
	tokenString := extractBearer(c)
	if tokenString == "" {
		return common.Unauthorized("missing Bearer token")
	}

	var payload Map
	err := common.ParseJWTToken(tokenString, &payload)
	if err != nil {
		return common.Unauthorized("invalid token")
	}

	resp := ValidateUserResponse{
		UserID: getInt(payload, "user_id"),
	}

	return c.JSON(resp)
}

// ValidateOpenclawToken
//
//	@Summary		Validate an openclaw token
//	@Description	Validate an openclaw JWT token from Authorization header and return openclaw data
//	@Tags			validate
//	@Produce		json
//	@Router			/validate/oc [post]
//	@Success		200	{object}	ValidateOpenclawResponse
//	@Failure		401	{object}	common.MessageResponse
func ValidateOpenclawToken(c *fiber.Ctx) error {
	tokenString := extractBearer(c)
	if tokenString == "" {
		return common.Unauthorized("missing Bearer token")
	}

	// parse unverified to get openclaw ID
	var claims OpenclawClaims
	parser := jwt.NewParser()
	_, _, err := parser.ParseUnverified(tokenString, &claims)
	if err != nil {
		return common.Unauthorized("invalid token")
	}

	// look up secret
	secret, err := GetOpenclawJwtSecret(claims.ID)
	if err != nil {
		return common.Unauthorized("openclaw not found")
	}

	// verify token with secret
	token, err := jwt.ParseWithClaims(tokenString, &OpenclawClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return common.Unauthorized("invalid token")
	}

	verifiedClaims, ok := token.Claims.(*OpenclawClaims)
	if !ok {
		return common.Unauthorized("invalid token claims")
	}

	// verify openclaw still exists
	_, err = GetOpenclawByID(verifiedClaims.ID)
	if err != nil {
		return common.Unauthorized("openclaw not found")
	}

	return c.JSON(ValidateOpenclawResponse{
		ID:         verifiedClaims.ID,
		OpenclawID: verifiedClaims.OpenclawID,
		UserID:     verifiedClaims.UserID,
		Type:       verifiedClaims.Type,
		Name:       verifiedClaims.Name,
	})
}

func extractBearer(c *fiber.Ctx) string {
	tokenString := c.Get("Authorization")
	if tokenString == "" {
		tokenString = c.Cookies("refresh")
	}
	if strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = tokenString[7:]
	}
	return strings.Trim(tokenString, " ")
}

func getInt(m map[string]any, key string) int {
	if v, ok := m[key]; ok {
		switch v := v.(type) {
		case float64:
			return int(v)
		case int:
			return v
		}
	}
	return 0
}

