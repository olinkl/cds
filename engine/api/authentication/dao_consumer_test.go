package authentication_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ovh/cds/engine/api/authentication"
	"github.com/ovh/cds/engine/api/bootstrap"
	"github.com/ovh/cds/engine/api/test"
	"github.com/ovh/cds/engine/api/user"
	"github.com/ovh/cds/sdk"
)

func TestLoadConsumer(t *testing.T) {
	db, _, end := test.SetupPG(t, bootstrap.InitiliazeDB)
	defer end()

	u := sdk.AuthentifiedUser{
		Username: sdk.RandomString(10),
	}
	require.NoError(t, user.Insert(db, &u))

	c1 := sdk.AuthConsumer{
		Name:               sdk.RandomString(10),
		Description:        sdk.RandomString(10),
		Type:               sdk.ConsumerLocal,
		Scopes:             []sdk.AuthConsumerScope{sdk.AuthConsumerScopeAdmin},
		AuthentifiedUserID: u.ID,
	}
	require.NoError(t, authentication.InsertConsumer(db, &c1))

	c2 := sdk.AuthConsumer{
		Name:               sdk.RandomString(10),
		Description:        sdk.RandomString(10),
		Type:               sdk.ConsumerBuiltin,
		Scopes:             []sdk.AuthConsumerScope{sdk.AuthConsumerScopeAdmin},
		AuthentifiedUserID: u.ID,
	}
	require.NoError(t, authentication.InsertConsumer(db, &c2))

	// LoadConsumerByID
	res, err := authentication.LoadConsumerByID(context.TODO(), db, sdk.RandomString(10))
	assert.Error(t, err)
	res, err = authentication.LoadConsumerByID(context.TODO(), db, c1.ID)
	assert.NoError(t, err)
	test.Equal(t, c1, res)

	// LoadConsumerByTypeAndUserID
	res, err = authentication.LoadConsumerByTypeAndUserID(context.TODO(), db, sdk.ConsumerLDAP, sdk.RandomString(10))
	assert.Error(t, err)
	res, err = authentication.LoadConsumerByTypeAndUserID(context.TODO(), db, sdk.ConsumerLocal, u.ID)
	assert.NoError(t, err)
	test.Equal(t, c1, res)

	// LoadConsumersByUserID
	cs, err := authentication.LoadConsumersByUserID(context.TODO(), db, sdk.RandomString(10))
	assert.NoError(t, err)
	assert.Equal(t, 0, len(cs))
	cs, err = authentication.LoadConsumersByUserID(context.TODO(), db, u.ID)
	assert.NoError(t, err)
	require.Equal(t, 2, len(cs))
	test.Equal(t, c1, cs[0])
	test.Equal(t, c2, cs[1])
}

func TestInsertConsumer(t *testing.T) {
	db, _, end := test.SetupPG(t, bootstrap.InitiliazeDB)
	defer end()

	u := sdk.AuthentifiedUser{
		Username: sdk.RandomString(10),
	}
	require.NoError(t, user.Insert(db, &u))

	c := sdk.AuthConsumer{
		Name:               sdk.RandomString(10),
		AuthentifiedUserID: u.ID,
	}
	require.NoError(t, authentication.InsertConsumer(db, &c))

	res, err := authentication.LoadConsumerByID(context.TODO(), db, c.ID)
	require.NoError(t, err)
	test.NotNil(t, res)
	test.Equal(t, c, res)
}

func TestUpdateConsumer(t *testing.T) {
	db, _, end := test.SetupPG(t, bootstrap.InitiliazeDB)
	defer end()

	u := sdk.AuthentifiedUser{
		Username: sdk.RandomString(10),
	}
	require.NoError(t, user.Insert(db, &u))

	c := sdk.AuthConsumer{
		Name:               sdk.RandomString(10),
		AuthentifiedUserID: u.ID,
	}
	require.NoError(t, authentication.InsertConsumer(db, &c))

	c.Description = sdk.RandomString(10)
	assert.NoError(t, authentication.UpdateConsumer(db, &c))

	res, err := authentication.LoadConsumerByID(context.TODO(), db, c.ID)
	assert.NoError(t, err)
	test.Equal(t, c, res)
}

func TestDeleteConsumer(t *testing.T) {
	db, _, end := test.SetupPG(t, bootstrap.InitiliazeDB)
	defer end()

	u := sdk.AuthentifiedUser{
		Username: sdk.RandomString(10),
	}
	require.NoError(t, user.Insert(db, &u))

	c := sdk.AuthConsumer{
		Name:               sdk.RandomString(10),
		AuthentifiedUserID: u.ID,
	}
	require.NoError(t, authentication.InsertConsumer(db, &c))

	_, err := authentication.LoadConsumerByID(context.TODO(), db, c.ID)
	assert.NoError(t, err)

	assert.NoError(t, authentication.DeleteConsumerByID(db, c.ID))

	_, err = authentication.LoadConsumerByID(context.TODO(), db, c.ID)
	assert.Error(t, err)
}