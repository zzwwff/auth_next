package models

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thanhpk/randstr"
	"gorm.io/gorm"

	"auth_next/config"
	"auth_next/utils/kong"
)

type Openclaw struct {
	ID        int       `json:"id" gorm:"primaryKey"`
	UserID    int       `json:"user_id" gorm:"index"`
	Name      string    `json:"name" gorm:"size:64"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
}

type OpenclawJwtSecret struct {
	ID     int    `json:"id" gorm:"primaryKey"`
	Secret string `json:"secret" gorm:"size:256"`
}

type OpenclawClaims struct {
	jwt.RegisteredClaims
	ID         int    `json:"id"`
	OpenclawID int    `json:"openclaw_id"`
	UserID     int    `json:"user_id"`
	Type       string `json:"type"`
	Name       string `json:"name"`
}

func (oc *Openclaw) CreateJWTToken() (accessToken, refreshToken string, err error) {
	var key, secret string

	if config.Config.Standalone {
		var ocJwtSecret OpenclawJwtSecret
		err = DB.Take(&ocJwtSecret, oc.ID).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				ocJwtSecret = OpenclawJwtSecret{
					ID:     oc.ID,
					Secret: randstr.Base62(32),
				}
				err = DB.Create(&ocJwtSecret).Error
				if err != nil {
					return "", "", err
				}
			} else {
				return "", "", err
			}
		}

		key = fmt.Sprintf("oc_%d", oc.ID)
		secret = ocJwtSecret.Secret
	} else {
		key, secret, err = kong.GetJwtSecretForOpenclaw(oc.ID)
		if err != nil {
			return "", "", err
		}
	}

	claim := OpenclawClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    key,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(99 * 365 * 24 * time.Hour)),
		},
		ID:         oc.ID,
		OpenclawID: oc.ID,
		UserID:     oc.UserID,
		Name:       oc.Name,
		Type:       JWTTypeAccess,
	}

	accessToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claim).SignedString([]byte(secret))
	if err != nil {
		return "", "", err
	}

	claim.Type = JWTTypeRefresh
	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claim).SignedString([]byte(secret))
	if err != nil {
		return "", "", err
	}

	return
}

func GetOpenclawByID(ocID int) (*Openclaw, error) {
	var oc Openclaw
	err := DB.Take(&oc, ocID).Error
	if err != nil {
		return nil, err
	}
	return &oc, nil
}

func ListOpenclawsByUserID(userID int) ([]Openclaw, error) {
	var ocs []Openclaw
	err := DB.Where("user_id = ?", userID).Find(&ocs).Error
	return ocs, err
}

func CreateOpenclawInDB(userID int, name string) (*Openclaw, error) {
	oc := Openclaw{
		UserID: userID,
		Name:   name,
	}
	err := DB.Create(&oc).Error
	if err != nil {
		return nil, err
	}
	return &oc, nil
}

func DeleteOpenclawByID(ocID int, userID int) error {
	result := DB.Where("id = ? AND user_id = ?", ocID, userID).Delete(&Openclaw{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	if config.Config.Standalone {
		DB.Delete(&OpenclawJwtSecret{}, ocID)
	} else {
		_ = kong.DeleteJwtCredentialForOpenclaw(ocID)
	}

	return nil
}

func GetOpenclawJwtSecret(ocID int) (secret string, err error) {
	if config.Config.Standalone {
		var ocJwtSecret OpenclawJwtSecret
		err = DB.Take(&ocJwtSecret, ocID).Error
		if err != nil {
			return "", err
		}
		return ocJwtSecret.Secret, nil
	}
	_, secret, err = kong.GetJwtSecretForOpenclaw(ocID)
	return secret, err
}
