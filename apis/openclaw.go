package apis

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/opentreehole/go-common"

	. "auth_next/models"
)

// CreateOpenclaw
//
//	@Summary		Create an openclaw instance
//	@Description	Create a new openclaw sandbox instance for the current user, returns JWT tokens
//	@Tags			openclaw
//	@Accept			json
//	@Produce		json
//	@Router			/openclaw [post]
//	@Param			json	body		CreateOpenclawRequest	true	"json"
//	@Success		200		{object}	CreateOpenclawResponse
//	@Failure		400		{object}	common.MessageResponse
//	@Failure		500		{object}	common.MessageResponse
func CreateOpenclaw(c *fiber.Ctx) error {
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	var body CreateOpenclawRequest
	err = common.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	oc, err := CreateOpenclawInDB(userID, body.Name)
	if err != nil {
		return err
	}

	access, refresh, err := oc.CreateJWTToken()
	if err != nil {
		return err
	}

	return c.JSON(CreateOpenclawResponse{
		ID:           oc.ID,
		Name:         oc.Name,
		UserID:       oc.UserID,
		AccessToken:  access,
		RefreshToken: refresh,
		Message:      "openclaw created",
	})
}

// DeleteOpenclaw
//
//	@Summary		Delete an openclaw instance
//	@Description	Delete an openclaw sandbox instance by ID, owner only
//	@Tags			openclaw
//	@Produce		json
//	@Router			/openclaw/{id} [delete]
//	@Success		200	{object}	common.MessageResponse
//	@Failure		404	{object}	common.MessageResponse
//	@Failure		500	{object}	common.MessageResponse
func DeleteOpenclaw(c *fiber.Ctx) error {
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	ocID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return common.BadRequest("invalid openclaw id")
	}

	err = DeleteOpenclawByID(ocID, userID)
	if err != nil {
		return err
	}

	return c.JSON(common.Message("openclaw deleted"))
}

// ListOpenclaw
//
//	@Summary		List openclaw instances
//	@Description	List all openclaw sandbox instances for the current user
//	@Tags			openclaw
//	@Produce		json
//	@Router			/openclaw [get]
//	@Success		200	{object}	ListOpenclawResponse
//	@Failure		500	{object}	common.MessageResponse
func ListOpenclaw(c *fiber.Ctx) error {
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	ocs, err := ListOpenclawsByUserID(userID)
	if err != nil {
		return err
	}

	responses := make([]OpenclawResponse, 0, len(ocs))
	for _, oc := range ocs {
		responses = append(responses, OpenclawResponse{
			ID:        oc.ID,
			Name:      oc.Name,
			UserID:    oc.UserID,
			CreatedAt: oc.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}

	return c.JSON(ListOpenclawResponse{Openclaws: responses})
}
