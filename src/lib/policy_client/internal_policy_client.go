package policy_client

import (
	"errors"
	"strings"

	"code.cloudfoundry.org/cf-networking-helpers/json_client"
	"code.cloudfoundry.org/lager"
)

type InternalClient struct {
	JsonClient json_client.JsonClient
}

type TagRequest struct {
	ID   string
	Type string
}

func NewInternal(logger lager.Logger, httpClient json_client.HttpClient, baseURL string) *InternalClient {
	return &InternalClient{
		JsonClient: json_client.New(logger, httpClient, baseURL),
	}
}

func (c *InternalClient) GetPolicies() ([]Policy, error) {
	var policies struct {
		Policies []Policy `json:"policies"`
	}
	err := c.JsonClient.Do("GET", "/networking/v1/internal/policies", nil, &policies, "")
	if err != nil {
		return nil, err
	}
	return policies.Policies, nil
}

func (c *InternalClient) GetPoliciesByID(ids ...string) ([]Policy, error) {
	var policies struct {
		Policies []Policy `json:"policies"`
	}
	if len(ids) == 0 {
		return nil, errors.New("ids cannot be empty")
	}
	err := c.JsonClient.Do("GET", "/networking/v1/internal/policies?id="+strings.Join(ids, ","), nil, &policies, "")
	if err != nil {
		return nil, err
	}
	return policies.Policies, nil
}

func (c *InternalClient) CreateOrGetTag(id, groupType string) (string, error) {
	var response struct {
		ID   string
		Type string
		Tag  string
	}
	err := c.JsonClient.Do("PUT", "/networking/v1/internal/tags", TagRequest{
		ID:   id,
		Type: groupType,
	}, &response, "")
	if err != nil {
		return "", err
	}
	return response.Tag, nil
}

func (c *InternalClient) HealthCheck() (bool, error) {
	var healthcheck struct {
		Healthcheck bool `json:"healthcheck"`
	}
	err := c.JsonClient.Do("GET", "/networking/v1/internal/healthcheck", nil, &healthcheck, "")
	if err != nil {
		return false, err
	}
	return healthcheck.Healthcheck, nil
}
