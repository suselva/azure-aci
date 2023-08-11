/*
Copyright (c) Microsoft Corporation.
Licensed under the Apache 2.0 license.
*/
package auth

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	_ "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/pkg/errors"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"github.com/virtual-kubelet/virtual-kubelet/trace"
)

type CloudEnvironmentName string

const (
	AzurePublicCloud       CloudEnvironmentName = "AzurePublicCloud"
	AzureUSGovernmentCloud CloudEnvironmentName = "AzureUSGovernmentCloud"
	AzureChinaCloud        CloudEnvironmentName = "AzureChinaCloud"
)

type ConfigInterface interface {
	GetMSICredential(ctx context.Context) (*azidentity.ManagedIdentityCredential, error)
	GetSPCredential(ctx context.Context) (*azidentity.ClientSecretCredential, error)
	GetAuthorizer(ctx context.Context, resource string) (autorest.Authorizer, error)
}

type Config struct {
	AKSCredential *aksCredential
	AuthConfig    *Authentication
	Cloud         cloud.Configuration
	Authorizer    autorest.Authorizer
}

// GetMSICredential retrieve MSI credential
func (c *Config) GetMSICredential(ctx context.Context) (*azidentity.ManagedIdentityCredential, error) {
	log.G(ctx).Debug("getting token using user identity")
	opts := &azidentity.ManagedIdentityCredentialOptions{
		ID: azidentity.ClientID(c.AuthConfig.UserIdentityClientId),
		ClientOptions: azcore.ClientOptions{
			Cloud: c.Cloud,
		}}
	msiCredential, err := azidentity.NewManagedIdentityCredential(opts)
	if err != nil {
		return nil, err
	}

	return msiCredential, nil
}

// GetSPCredential retrieve SP credential
func (c *Config) GetSPCredential(ctx context.Context) (*azidentity.ClientSecretCredential, error) {
	log.G(ctx).Debug("getting token using service principal")
	opts := &azidentity.ClientSecretCredentialOptions{
		ClientOptions: azcore.ClientOptions{
			Cloud: c.Cloud,
		},
	}
	spCredential, err := azidentity.NewClientSecretCredential(c.AuthConfig.TenantID, c.AuthConfig.ClientID, c.AuthConfig.ClientSecret, opts)
	if err != nil {
		return nil, err
	}

	return spCredential, nil
}

// GetAuthorizer return autorest authorizer.
func (c *Config) GetAuthorizer(ctx context.Context, resource string) (autorest.Authorizer, error) {
	var auth autorest.Authorizer
	var err error

	var token *adal.ServicePrincipalToken
	isUserIdentity := len(c.AuthConfig.ClientID) == 0

	if isUserIdentity {
		log.G(ctx).Debug("getting token using user identity")

		token, err = adal.NewServicePrincipalTokenFromManagedIdentity(
			resource, &adal.ManagedIdentityOptions{ClientID: c.AuthConfig.UserIdentityClientId})
		if err != nil {
			return nil, err
		}
	} else {
		log.G(ctx).Debug("getting token using service principal")

		oauthConfig, err := adal.NewOAuthConfig(
			c.Cloud.ActiveDirectoryAuthorityHost, c.AuthConfig.TenantID)
		if err != nil {
			return nil, err
		}
		token, err = adal.NewServicePrincipalToken(
			*oauthConfig, c.AuthConfig.ClientID, c.AuthConfig.ClientSecret, resource)
		if err != nil {
			return nil, err
		}
	}
	auth = autorest.NewBearerAuthorizer(token)
	return auth, err
}

// SetAuthConfig sets the configuration needed for Authentication.
func (c *Config) SetAuthConfig(ctx context.Context) error {
	ctx, span := trace.StartSpan(ctx, "auth.SetAuthConfig")
	defer span.End()
	fmt.Println("SetAuthConfig Start")

	var err error
	c.AuthConfig = &Authentication{}
	c.Cloud = cloud.AzurePublic

	if authFilepath := os.Getenv("AZURE_AUTH_LOCATION"); authFilepath != "" {
		fmt.Printf("getting Azure auth config from file, path: %s \r\n", authFilepath)

		log.G(ctx).Debug("getting Azure auth config from file, path: %s", authFilepath)

		b, err2 := ioutil.ReadFile(authFilepath)
		if err2 != nil {
			fmt.Printf("File read error %s \r\n", err2)
		}

		fmt.Println(string(b))

		auth := &Authentication{}
		err = auth.newAuthenticationFromFile(authFilepath)
		if err != nil {
			fmt.Println("cannot get Azure auth config. Please make sure AZURE_AUTH_LOCATION env variable is set correctly")
			return errors.Wrap(err, "cannot get Azure auth config. Please make sure AZURE_AUTH_LOCATION env variable is set correctly")
		}
		c.AuthConfig = auth
	} else {
		fmt.Println("getting Azure auth config from file, NOT FOUND")
	}

	if aksCredFilepath := os.Getenv("AKS_CREDENTIAL_LOCATION"); aksCredFilepath != "" {
		fmt.Printf("getting AKS cred from file, path: %s\r\n", aksCredFilepath)
		log.G(ctx).Debug("getting AKS cred from file, path: %s", aksCredFilepath)

		b, err2 := ioutil.ReadFile(aksCredFilepath)
		if err2 != nil {
			fmt.Printf("File read error %s \r\n", err2)
		}
		fmt.Println(string(b))

		c.AKSCredential, err = newAKSCredential(ctx, aksCredFilepath)
		if err != nil {
			fmt.Println("cannot get AKS credential config. Please make sure AKS_CREDENTIAL_LOCATION env variable is set correctly")
			return errors.Wrap(err, "cannot get AKS credential config. Please make sure AKS_CREDENTIAL_LOCATION env variable is set correctly")
		}

		var clientId string
		if !strings.EqualFold(c.AKSCredential.ClientID, "msi") {
			clientId = c.AKSCredential.ClientID
		}
		fmt.Printf("AKSCredential.ClientID : %s\r\n", clientId)

		//Set Azure cloud environment
		c.Cloud = getCloudConfiguration(c.AKSCredential.Cloud)
		c.AuthConfig = NewAuthentication(
			clientId,
			c.AKSCredential.ClientSecret,
			c.AKSCredential.SubscriptionID,
			c.AKSCredential.TenantID,
			c.AKSCredential.UserAssignedIdentityID)
	} else {
		fmt.Println("getting AKS cred from file, NOT FOUND")
	}

	if clientID := os.Getenv("AZURE_CLIENT_ID"); clientID != "" {
		fmt.Printf("azure client ID env variable AZURE_CLIENT_ID is set %s \r\n", clientID)
		log.G(ctx).Debug("azure client ID env variable AZURE_CLIENT_ID is set")
		c.AuthConfig.ClientID = clientID
	} else {
		fmt.Println("azure client ID env variable AZURE_CLIENT_ID is not set")
	}

	if clientSecret := os.Getenv("AZURE_CLIENT_SECRET"); clientSecret != "" {
		fmt.Printf("azure client secret env variable AZURE_CLIENT_SECRET is set %s \r\n", clientSecret)
		log.G(ctx).Debug("azure client secret env variable AZURE_CLIENT_SECRET is set")
		c.AuthConfig.ClientSecret = clientSecret
	} else {
		fmt.Println("azure client secret env variable AZURE_CLIENT_SECRET is not set")
	}

	if userIdentityClientId := os.Getenv("VIRTUALNODE_USER_IDENTITY_CLIENTID"); userIdentityClientId != "" {
		fmt.Printf("user identity client ID env variable VIRTUALNODE_USER_IDENTITY_CLIENTID is set %s \r\n", userIdentityClientId)
		log.G(ctx).Debug("user identity client ID env variable VIRTUALNODE_USER_IDENTITY_CLIENTID is set")
		c.AuthConfig.UserIdentityClientId = userIdentityClientId
	} else {
		fmt.Println("user identity client ID env variable VIRTUALNODE_USER_IDENTITY_CLIENTID is not set")
	}

	isUserIdentity := len(c.AuthConfig.ClientID) == 0

	if isUserIdentity {
		fmt.Println("isUserIdentity")

		if len(c.AuthConfig.UserIdentityClientId) == 0 {
			fmt.Println("neither AZURE_CLIENT_ID or VIRTUALNODE_USER_IDENTITY_CLIENTID is being set")
			return fmt.Errorf("neither AZURE_CLIENT_ID or VIRTUALNODE_USER_IDENTITY_CLIENTID is being set")
		}

		fmt.Println("using user identity for Authentication")
		log.G(ctx).Info("using user identity for Authentication")
	} else {
		fmt.Println("NOT UserIdentity")
	}

	if tenantID := os.Getenv("AZURE_TENANT_ID"); tenantID != "" {
		fmt.Printf("azure tenant ID env variable AZURE_TENANT_ID is set %s \r\n", tenantID)
		log.G(ctx).Debug("azure tenant ID env variable AZURE_TENANT_ID is set")
		c.AuthConfig.TenantID = tenantID
	} else {
		fmt.Println("azure tenant ID env variable AZURE_TENANT_ID is not set")
	}

	if subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID"); subscriptionID != "" {
		fmt.Printf("azure subscription ID env variable AZURE_SUBSCRIPTION_ID is set %s \r\n", subscriptionID)
		log.G(ctx).Debug("azure subscription ID env variable AZURE_SUBSCRIPTION_ID is set")
		c.AuthConfig.SubscriptionID = subscriptionID
	} else {
		fmt.Println("azure subscription ID env variable AZURE_SUBSCRIPTION_ID is not set")
	}

	resource := c.Cloud.Services[cloud.ResourceManager].Endpoint

	c.Authorizer, err = c.GetAuthorizer(ctx, resource)
	if err != nil {
		return err
	}

	return nil
}

func getCloudConfiguration(cloudName string) cloud.Configuration {
	switch cloudName {
	case string(AzurePublicCloud):
		return cloud.AzurePublic
	case string(AzureUSGovernmentCloud):
		return cloud.AzureGovernment
	case string(AzureChinaCloud):
		return cloud.AzureChina
	}
	panic("cloud config does not exist")
}
