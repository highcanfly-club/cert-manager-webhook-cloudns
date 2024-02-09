// Description: This file contains the implementation of the Cloudns DNS01 solver.
// Some of the code is taken from the cert-manager project and some code is taken from the ixoncloud/cert-manager-webhook-cloudns project.
package cloudns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
	k8sextapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const defaultBaseURL = "https://api.cloudns.net/dns/"

type apiResponse struct {
	Status            string `json:"status"`
	StatusDescription string `json:"statusDescription"`
}

type Zone struct {
	Name              string
	Type              string
	Zone              string
	Status            string // is an integer, but cast as string
	StatusDescription string
}

// TXTRecord a TXT record
type TXTRecord struct {
	ID       int    `json:"id,string"`
	Type     string `json:"type"`
	Host     string `json:"host"`
	Record   string `json:"record"`
	Failover int    `json:"failover,string"`
	TTL      int    `json:"ttl,string"`
	Status   int    `json:"status"`
}

type TXTRecords map[string]TXTRecord

// ClouDNSClient ClouDNS client
type ClouDNSClient struct {
	authIDType   string
	authID       string
	authPassword string
	TTL          int
	HTTPClient   *http.Client
	BaseURL      *url.URL
}

// NewClouDNSClient creates a ClouDNS client
func NewClouDNSClient(authID string, authIDType string, authPassword string, ttl int) (*ClouDNSClient, error) {
	if authID == "" {
		return nil, fmt.Errorf("credentials missing: authID")
	}

	if authPassword == "" {
		return nil, fmt.Errorf("credentials missing: authPassword")
	}

	baseURL, err := url.Parse(defaultBaseURL)
	if err != nil {
		return nil, err
	}

	return &ClouDNSClient{
		authID:       authID,
		authIDType:   authIDType,
		authPassword: authPassword,
		HTTPClient:   &http.Client{},
		BaseURL:      baseURL,
		TTL:          ttl,
	}, nil
}

// GetZone Get domain name information for a FQDN
func (c *ClouDNSClient) GetZone(authFQDN string) (*Zone, error) {
	authZone, err := dns01.FindZoneByFqdn(authFQDN)
	if err != nil {
		return nil, err
	}

	authZoneName := dns01.UnFqdn(authZone)

	reqURL := *c.BaseURL
	reqURL.Path += "get-zone-info.json"

	q := reqURL.Query()
	q.Add("domain-name", authZoneName)
	reqURL.RawQuery = q.Encode()

	result, err := c.doRequest(http.MethodGet, &reqURL)
	if err != nil {
		return nil, err
	}

	var zone Zone

	if len(result) > 0 {
		if err = json.Unmarshal(result, &zone); err != nil {
			return nil, fmt.Errorf("zone unmarshaling error: %v", err)
		}
	}

	// Handle zone info fail
	if zone.Status == "Failed" {
		return nil, fmt.Errorf("could not get zone info: %v", zone.StatusDescription)
	}

	if zone.Name == authZoneName {
		return &zone, nil
	}

	return nil, fmt.Errorf("zone %s not found for authFQDN %s", authZoneName, authFQDN)
}

// FindTxtRecord return the TXT record a zone ID and a FQDN
func (c *ClouDNSClient) FindTxtRecord(zoneName, fqdn string) (*TXTRecord, error) {
	host := dns01.UnFqdn(strings.TrimSuffix(dns01.UnFqdn(fqdn), zoneName))

	reqURL := *c.BaseURL
	reqURL.Path += "records.json"

	q := reqURL.Query()
	q.Add("domain-name", zoneName)
	q.Add("host", host)
	q.Add("type", "TXT")
	reqURL.RawQuery = q.Encode()

	result, err := c.doRequest(http.MethodGet, &reqURL)
	if err != nil {
		return nil, err
	}

	// the API returns [] when there is no records.
	if string(result) == "[]" {
		return nil, nil
	}

	var records TXTRecords
	if err = json.Unmarshal(result, &records); err != nil {
		return nil, fmt.Errorf("TXT record unmarshaling error: %v: %s", err, string(result))
	}

	for _, record := range records {
		if record.Host == host && record.Type == "TXT" {
			return &record, nil
		}
	}

	return nil, nil
}

// AddTxtRecord add a TXT record
func (c *ClouDNSClient) AddTxtRecord(zoneName string, fqdn, value string, ttl int) error {
	host := dns01.UnFqdn(strings.TrimSuffix(dns01.UnFqdn(fqdn), zoneName))

	reqURL := *c.BaseURL
	reqURL.Path += "add-record.json"

	q := reqURL.Query()
	q.Add("domain-name", zoneName)
	q.Add("host", host)
	q.Add("record", value)
	q.Add("ttl", strconv.Itoa(ttlRounder(ttl)))
	q.Add("record-type", "TXT")
	reqURL.RawQuery = q.Encode()

	raw, err := c.doRequest(http.MethodPost, &reqURL)
	if err != nil {
		return err
	}

	resp := apiResponse{}
	if err = json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("apiResponse unmarshaling error: %v: %s", err, string(raw))
	}

	if resp.Status != "Success" {
		return fmt.Errorf("fail to add TXT record: %s %s", resp.Status, resp.StatusDescription)
	}

	return nil
}

// RemoveTxtRecord remove a TXT record
func (c *ClouDNSClient) RemoveTxtRecord(recordID int, zoneName string) error {
	reqURL := *c.BaseURL
	reqURL.Path += "delete-record.json"

	q := reqURL.Query()
	q.Add("domain-name", zoneName)
	q.Add("record-id", strconv.Itoa(recordID))
	reqURL.RawQuery = q.Encode()

	raw, err := c.doRequest(http.MethodPost, &reqURL)
	if err != nil {
		return err
	}

	resp := apiResponse{}
	if err = json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("apiResponse unmarshaling error: %v: %s", err, string(raw))
	}

	if resp.Status != "Success" {
		return fmt.Errorf("fail to add TXT record: %s %s", resp.Status, resp.StatusDescription)
	}

	return nil
}

func (c *ClouDNSClient) doRequest(method string, url *url.URL) (json.RawMessage, error) {
	req, err := c.buildRequest(method, url)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New(toUnreadableBodyMessage(req, content))
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("invalid code (%v), error: %s", resp.StatusCode, content)
	}
	return content, nil
}

func (c *ClouDNSClient) buildRequest(method string, url *url.URL) (*http.Request, error) {
	q := url.Query()
	q.Add(c.authIDType, c.authID)
	q.Add("auth-password", c.authPassword)
	url.RawQuery = q.Encode()

	req, err := http.NewRequest(method, url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("invalid request: %v", err)
	}

	return req, nil
}

func toUnreadableBodyMessage(req *http.Request, rawBody []byte) string {
	return fmt.Sprintf("the request %s sent a response with a body which is an invalid format: %q", req.URL, string(rawBody))
}

// https://www.cloudns.net/wiki/article/58/
// Available TTL's:
// 60 = 1 minute
// 300 = 5 minutes
// 900 = 15 minutes
// 1800 = 30 minutes
// 3600 = 1 hour
// 21600 = 6 hours
// 43200 = 12 hours
// 86400 = 1 day
// 172800 = 2 days
// 259200 = 3 days
// 604800 = 1 week
// 1209600 = 2 weeks
// 2592000 = 1 month
func ttlRounder(ttl int) int {
	validTTLs := []int{60, 300, 900, 1800, 3600, 21600, 43200, 86400, 172800, 259200, 604800, 1209600, 2592000}
	closestTTL := validTTLs[0]
	for _, validTTL := range validTTLs {
		if abs(ttl-validTTL) < abs(ttl-closestTTL) {
			closestTTL = validTTL
		}
	}
	return closestTTL
}

// Abs returns the absolute value of x.
// this is a helper function to avoid importing math
// which is working with float64
// https://golang.org/src/math/abs.go
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

type cloudnsSolver struct {
	name       string
	server     *dns.Server
	txtRecords map[string]string
	k8sclient  *kubernetes.Clientset
	client     *ClouDNSClient
	sync.RWMutex
}

func (e *cloudnsSolver) Name() string {
	return e.name
}

func NewSolver() webhook.Solver {
	return &cloudnsSolver{}
}

// clouDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.

type cloudnsProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
	AuthID          string                   `json:"authId"`
	AuthIDType      string                   `json:"authIdType"`
	TTL             int                      `json:"ttl"`
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *k8sextapi.JSON) (cloudnsProviderConfig, error) {
	cfg := cloudnsProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	cfg.TTL = ttlRounder(cfg.TTL)

	return cfg, nil
}

// return the credentials for the given challenge
func (e *cloudnsSolver) setCredentials(ch *acme.ChallengeRequest) error {
	if e.client != nil && e.client.authID != "" && e.client.authPassword != "" && e.client.authIDType != "" && e.k8sclient != nil {
		return nil
	}

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	secretName := cfg.APIKeySecretRef.LocalObjectReference.Name
	klog.V(6).Infof("Try to load secret `%s` with key `%s`", secretName, cfg.APIKeySecretRef.Key)
	sec, err := e.k8sclient.CoreV1().Secrets(ch.ResourceNamespace).Get(context.Background(), secretName, k8smetav1.GetOptions{})

	if err != nil {
		return fmt.Errorf("unable to get secret `%s`; %v", secretName, err)
	}

	secBytes, ok := sec.Data[cfg.APIKeySecretRef.Key]

	if !ok {
		return fmt.Errorf("key %q not found in secret \"%s/%s\"", cfg.APIKeySecretRef.Key, cfg.APIKeySecretRef.LocalObjectReference.Name, ch.ResourceNamespace)
	}

	apiKey := string(secBytes)

	e.client, err = NewClouDNSClient(cfg.AuthID, cfg.AuthIDType, apiKey, cfg.TTL)
	if err != nil {
		return fmt.Errorf("failed to create new ClouDNS provider: %w", err)
	}

	return nil
}

func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 5 {
		return apiKey
	}
	return strings.Repeat("*", len(apiKey)-5) + apiKey[len(apiKey)-5:]
}

func (e *cloudnsSolver) Present(ch *acme.ChallengeRequest) error {
	e.Lock()
	e.txtRecords[ch.ResolvedFQDN] = ch.Key
	err := e.setCredentials(ch)

	if err != nil {
		return err
	}
	klog.V(6).Infof("Presenting challenge for %s using type: %s,authID: %s and key: %s", ch.ResolvedFQDN, e.client.authIDType, e.client.authID, maskAPIKey(e.client.authPassword))
	zone, err := e.client.GetZone(ch.ResolvedFQDN)
	if err != nil {
		return fmt.Errorf("ClouDNS: %v", err)
	}

	err = e.client.AddTxtRecord(zone.Name, ch.ResolvedFQDN, e.txtRecords[ch.ResolvedFQDN], e.client.TTL)
	if err != nil {
		return fmt.Errorf("ClouDNS: %v", err)
	}
	e.Unlock()
	return nil
}

func (e *cloudnsSolver) CleanUp(ch *acme.ChallengeRequest) error {
	e.Lock()
	zone, err := e.client.GetZone(ch.ResolvedFQDN)
	if err != nil {
		return fmt.Errorf("ClouDNS: %v", err)
	}

	record, err := e.client.FindTxtRecord(zone.Name, ch.ResolvedFQDN)
	if err != nil {
		return fmt.Errorf("ClouDNS: %v", err)
	}

	if record == nil {
		return nil
	}

	err = e.client.RemoveTxtRecord(record.ID, zone.Name)
	if err != nil {
		return fmt.Errorf("ClouDNS: %v", err)
	}

	delete(e.txtRecords, ch.ResolvedFQDN)
	e.Unlock()

	return nil
}

func (e *cloudnsSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	e.k8sclient = cl

	go func(done <-chan struct{}) {
		<-done
		if err := e.server.Shutdown(); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		}
	}(stopCh)
	go func() {
		if err := e.server.ListenAndServe(); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}
	}()

	return nil
}

func New(port string) webhook.Solver {
	e := &cloudnsSolver{
		name:       "cloudns",
		txtRecords: make(map[string]string),
	}
	e.server = &dns.Server{
		Addr:    ":" + port,
		Net:     "udp",
		Handler: dns.HandlerFunc(e.handleDNSRequest),
	}
	return e
}
