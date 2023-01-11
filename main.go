package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/wedos"
	coreV1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&wedosProviderSolver{},
	)
}

type wedosProviderSolver struct {
	client *kubernetes.Clientset
}

type wedosProviderConfig struct {
	APIUsername     string                   `json:"apiUsername"`
	APIKeySecretRef coreV1.SecretKeySelector `json:"apiKeySecretRef"`
}

func (e *wedosProviderSolver) Name() string {
	return "wedos"
}

func (e *wedosProviderSolver) validate(cfg *wedosProviderConfig) error {
	// Try to load the API key
	if cfg.APIKeySecretRef.LocalObjectReference.Name == "" {
		return errors.New("API token field were not provided")
	}

	return nil
}

func (e *wedosProviderSolver) provider(ch *acme.ChallengeRequest) (*wedos.DNSProvider, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	if err := e.validate(&cfg); err != nil {
		return nil, err
	}

	ctx, ctxCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer ctxCancel()
	sec, err := e.client.CoreV1().
		Secrets(ch.ResourceNamespace).
		Get(ctx, cfg.APIKeySecretRef.LocalObjectReference.Name, metaV1.GetOptions{})
	if err != nil {
		return nil, err
	}
	secBytes, ok := sec.Data[cfg.APIKeySecretRef.Key]
	if !ok {
		return nil, fmt.Errorf("key %q not found in secret \"%s/%s\"",
			cfg.APIKeySecretRef.Key,
			cfg.APIKeySecretRef.LocalObjectReference.Name,
			ch.ResourceNamespace)
	}

	wedosConfig := wedos.NewDefaultConfig()
	wedosConfig.Username = cfg.APIUsername
	wedosConfig.Password = string(secBytes)
	return wedos.NewDNSProviderConfig(wedosConfig)
}

func (e *wedosProviderSolver) Present(ch *acme.ChallengeRequest) error {
	provider, err := e.provider(ch)
	if err != nil {
		return err
	}

	fqdn, value := dns01.GetRecord(ch.ResolvedZone, ch.Key)
	authZone, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		return err
	}

	fmt.Println("Present", ch, ch.ResolvedZone, fqdn, authZone)
	return provider.Present(ch.ResolvedZone, "", ch.Key)
}

func (e *wedosProviderSolver) CleanUp(ch *acme.ChallengeRequest) error {
	provider, err := e.provider(ch)
	if err != nil {
		return err
	}

	fqdn, value := dns01.GetRecord(ch.ResolvedZone, ch.Key)
	authZone, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		return err
	}

	fmt.Println("Cleanup", ch)
	fmt.Println("Cleanup", ch, ch.ResolvedZone, fqdn, authZone)
	return provider.CleanUp(ch.ResolvedZone, "", ch.Key)
}

func (e *wedosProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	e.client = cl
	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (wedosProviderConfig, error) {
	cfg := wedosProviderConfig{}
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
