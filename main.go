package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	cognitosrp "github.com/alexrudd/cognito-srp"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"golang.org/x/net/http2"

	aws2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/aws/aws-sdk-go/service/iot"
	"github.com/davecgh/go-spew/spew"
)

var (
	username = flag.String("username", "", "Homemate username")
	password = flag.String("password", "", "Homemate password")
)

func main() {
	flag.Parse()

	var ctx = context.Background()

	mySession := session.Must(session.NewSession())

	svc := cognitoidentity.New(mySession, aws.NewConfig().WithRegion("us-east-1"))

	csrp, _ := cognitosrp.NewCognitoSRP(*username, *password, "us-east-1_GUFWfhI7g", "19efs8tgqe942atbqmot5m36t3", nil)

	cfg, _ := external.LoadDefaultAWSConfig()
	cfg.Region = endpoints.UsEast1RegionID

	cfg.Credentials = aws2.AnonymousCredentials

	cognitoIdentityProvider2 := cip.New(cfg)

	initiateAuthRequest := cognitoIdentityProvider2.InitiateAuthRequest(&cip.InitiateAuthInput{
		AuthFlow:       cip.AuthFlowTypeUserSrpAuth,
		ClientId:       aws.String(csrp.GetClientId()),
		AuthParameters: csrp.GetAuthParams(),
	})

	initiateAuthRequest.Build()

	initiateAutheRespond, err := initiateAuthRequest.Send(ctx)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	var IdToken string
	var RefreshToken string

	if initiateAutheRespond.ChallengeName == cip.ChallengeNameTypePasswordVerifier {
		challengeInput, _ := csrp.PasswordVerifierChallenge(initiateAutheRespond.ChallengeParameters, time.Now())
		chal := cognitoIdentityProvider2.RespondToAuthChallengeRequest(challengeInput)
		responseToAutheChallengeResponse, erro := chal.Send(ctx)
		if erro != nil {
			fmt.Println(err.Error())
			return
		}
		IdToken = *responseToAutheChallengeResponse.AuthenticationResult.IdToken
		RefreshToken = *responseToAutheChallengeResponse.AuthenticationResult.RefreshToken
	}

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	initiateAuthRequest = cognitoIdentityProvider2.InitiateAuthRequest(&cip.InitiateAuthInput{
		AuthFlow: cip.AuthFlowTypeRefreshTokenAuth,
		ClientId: aws.String(csrp.GetClientId()),
		AuthParameters: map[string]string{
			"REFRESH_TOKEN": RefreshToken,
		},
	})

	initiateAuthRequest.Build()

	initiateAutheRespond, err = initiateAuthRequest.Send(ctx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	IdToken = *initiateAutheRespond.AuthenticationResult.IdToken

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	params := &cognitoidentity.GetIdInput{
		IdentityPoolId: aws.String("us-east-1:ebd95d52-9995-45da-b059-56b865a18379"), // Required
		Logins: map[string]*string{
			"cognito-idp.us-east-1.amazonaws.com/us-east-1_GUFWfhI7g": aws.String(IdToken), // Required
		},
	}

	getID, err := svc.GetId(params)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	credentialsForIdentityInput := &cognitoidentity.GetCredentialsForIdentityInput{
		IdentityId: getID.IdentityId,
		Logins: map[string]*string{
			"cognito-idp.us-east-1.amazonaws.com/us-east-1_GUFWfhI7g": aws.String(IdToken),
		},
	}

	credentialsForIdentity, err := svc.GetCredentialsForIdentity(credentialsForIdentityInput)

	spew.Dump(credentialsForIdentity)

	// cred := credentials.NewStaticCredentialsFromCreds(credentials.Value{AccessKeyID: *credentialsForIdentity.Credentials.AccessKeyId, SecretAccessKey: *credentialsForIdentity.Credentials.SecretKey, SessionToken: *credentialsForIdentity.Credentials.SessionToken})
	// spew.Dump(cred)

	// signer := v4.NewSigner(cred)

	mySession.Config.WithCredentials(credentials.NewStaticCredentials(
		*credentialsForIdentity.Credentials.AccessKeyId,
		*credentialsForIdentity.Credentials.SecretKey,
		*credentialsForIdentity.Credentials.SessionToken))

	mySession.Config.WithRegion("us-east-1")

	signer := v4.NewSigner(credentials.NewStaticCredentials(
		*credentialsForIdentity.Credentials.AccessKeyId,
		*credentialsForIdentity.Credentials.SecretKey,
		*credentialsForIdentity.Credentials.SessionToken,
	))
	// Expiration

	svc23 := iot.New(mySession)
	svc23.AttachPolicy()

	// spew.Dump(signer)

	tr2 := &http2.Transport{
		TLSClientConfig: &tls.Config{CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
			PreferServerCipherSuites: true,
			InsecureSkipVerify:       true,
			MinVersion:               tls.VersionTLS11,
			MaxVersion:               tls.VersionTLS11,
		},
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{CipherSuites: []uint16{

			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,

			// tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			// tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			// tls.TLS_RSA_WITH_AES_128_CBC_SHA256,

			// tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		},
			// PreferServerCipherSuites: true,
			// InsecureSkipVerify:       true,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			NextProtos: []string{
				"http/1.1",
			},
			ServerName: "a3q27gia9qg3zy-ats.iot.us-east-1.amazonaws.com",
		},
	}

	client := &http.Client{Transport: tr}

	client2 := &http.Client{Transport: tr2}

	// req.Header.Set("Sec-WebSocket-Protocol", "mqtt")
	// req.Header.Set("Upgrade", "websocket")
	// req.Header.Set("Connection", "Upgrade")
	// req.Header.Set("Sec-WebSocket-Version", "13")
	// req.Header.Set("accept-encoding", "gzip")
	// req.Header.Set("user-agent", "okhttp/3.12.1")

	// q := url.Values{}
	// q.Add("ver", "2.8.2")
	// q.Add("dev", "Nexus 5X")
	// q.Add("os", "8.1.0")

	// req.URL.RawQuery = q.Encode()

	// cred := credentials.NewStaticCredentialsFromCreds(
	// 	credentials.Value{
	// 		AccessKeyID:     *credentialsForIdentity.Credentials.AccessKeyId,
	// 		SecretAccessKey: *credentialsForIdentity.Credentials.SecretKey,
	// 		SessionToken:    *credentialsForIdentity.Credentials.SessionToken,
	// 	})

	// signer := v4.NewSigner(cred)

	// awsauth.Sign(req, awsauth.Credentials{
	// 	AccessKeyID:     *credentialsForIdentity.Credentials.AccessKeyId,
	// 	SecretAccessKey: *credentialsForIdentity.Credentials.SecretKey,
	// 	SecurityToken:   *credentialsForIdentity.Credentials.SessionToken, // STS (optional)
	// })

	// spew.Dump(signer)

	req10, err := http.NewRequest("GET", "https://app-prod.mysa.cloud/users/readingsForUser", nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	req10.Header.Set("accept", "application/json")
	req10.Header.Set("authorization", IdToken)
	req10.Header.Set("accept-encoding", "gzip")
	req10.Header.Set("user-agent", "okhttp/3.12.1")
	r := url.Values{}
	r.Add("ver", "2.8.2")
	r.Add("dev", "Nexus 5X")
	r.Add("os", "8.1.0")

	req10.URL.RawQuery = r.Encode()
	resp10, err2 := client2.Do(req10)

	if err2 != nil {
		fmt.Println(err2.Error())
		return
	}

	var jsonResult map[string]interface{}

	json.NewDecoder(resp10.Body).Decode(&jsonResult)
	spew.Dump(jsonResult)

	// req, err := http.NewRequest("GET", "https://a3q27gia9qg3zy-ats.iot.us-east-1.amazonaws.com", nil)
	// if err != nil {
	// 	log.Print(err)
	// 	// os.Exit(1)
	// }
	// spew.Dump(req.Body)
	// signer.DisableHeaderHoisting = true
	// signer.DisableURIPathEscaping = true
	// signer.DisableRequestBodyOverwrite = true
	// signer.UnsignedPayload = true

	// _, err = signer.Presign(req, nil, "iotdevicegateway", "us-east-1", 60*time.Minute, time.Now().Add(-5*time.Hour))

	body := bytes.NewReader([]byte{})

	endpoint := "a3q27gia9qg3zy-ats.iot.us-east-1.amazonaws.com"
	originalURL, err := url.Parse(fmt.Sprintf("https://%s/mqtt", endpoint))

	key, _ := generateChallengeKey()

	req22 := &http.Request{
		Method: "GET",
		URL:    originalURL,
		Header: map[string][]string{
			// "Host": {"a3q27gia9qg3zy-ats.iot.us-east-1.amazonaws.com"},
			// 	"Sec-WebSocket-Protocol": {"mqtt"},
			// 	"Upgrade":                {"websocket"},
			// 	"Connection":             {"Upgrade"},
			// 	"Sec-WebSocket-Version":  {"13"},
			// 	"Sec-WebSocket-Key":      {key},
			// 	"accept-encoding":        {"gzip"},
			// 	"user-agent":             {"okhttp/3.12.1"},
		},
	}

	// req.Header.Set("user-agent", "okhttp/3.12.1")
	req22.Host = "a3q27gia9qg3zy-ats.iot.us-east-1.amazonaws.com"
	_, err = signer.Presign(
		req22, body,
		"iotdevicegateway", "us-east-1",
		time.Hour*24, time.Now(),
	)

	req22.Header.Set("Sec-WebSocket-Protocol", "mqtt")
	req22.Header.Set("Upgrade", "websocket")
	req22.Header.Set("Connection", "Upgrade")
	req22.Header.Set("Sec-WebSocket-Version", "13")
	req22.Header.Set("Sec-WebSocket-Key", key)
	req22.Header.Set("accept-encoding", "gzip")
	req22.Header.Set("user-agent", "okhttp/3.12.1")
	req22.Header.Set("origin", "https://a3q27gia9qg3zy-ats.iot.us-east-1.amazonaws.com")

	resp, err2 := client.Do(req22)
	spew.Dump(resp)

	// req.URL.Path = "/mqtt"
	// request.SanitizeHostForHeader(req)

	// req.Header.Set("Sec-WebSocket-Protocol", "mqtt")
	// req.Header.Set("Upgrade", "websocket")
	// req.Header.Set("Connection", "Upgrade")
	// req.Header.Set("Sec-WebSocket-Version", "13")
	// req.Header.Set("Sec-WebSocket-Key", key)

	// req.Header.Set("accept-encoding", "gzip")
	// req.Header.Set("user-agent", "okhttp/3.12.1")
	// req.Header.Set("host", "a3q27gia9qg3zy-ats.iot.us-east-1.amazonaws.com")
	// // req.Host = "a3q27gia9qg3zy-ats.iot.us-east-1.amazonaws.com"

	// req.Header.Set("Origin", "https://a3q27gia9qg3zy-ats.iot.us-east-1.amazonaws.com")

	// // spew.Dump(bob)
	// // awsauth.Sign(req, awsauth.Credentials{
	// // 	AccessKeyID:     *credentialsForIdentity.Credentials.AccessKeyId,
	// // 	SecretAccessKey: *credentialsForIdentity.Credentials.SecretKey,
	// // 	SecurityToken:   *credentialsForIdentity.Credentials.SessionToken,
	// // })
	// _, err = signer.Presign(req, nil, "iotdevicegateway", "us-east-1", 60*time.Minute, time.Now().Add(-5*time.Hour))

	// resp, err2 := client.Do(req)
	// spew.Dump(req.URL)
	// // spew.Dump(credentialsForIdentity.Credentials.SessionToken)
	// spew.Dump(resp.Status)
	// spew.Dump(time.Now())

	// spew.Dump(mySession)
	// ps := presigner.New(mySession)
	// wssURL, err := ps.PresignWssNow("a3q27gia9qg3zy-ats.iot.us-east-1.amazonaws.com")

	// o := &awsiot.Options{
	// 	ClientID:                 "86db252d-8aa2-41b2-9b3e-ccc9cc98a9a7",
	// 	Region:                   "us-east-1",
	// 	BaseReconnectTime:        time.Millisecond * 50,
	// 	MaximumReconnectTime:     time.Second * 2,
	// 	MinimumConnectionTime:    time.Second * 2,
	// 	Keepalive:                time.Second * 2,
	// 	URL:                      wssURL,
	// 	Debug:                    true,
	// 	Qos:                      1,
	// 	Retain:                   false,
	// 	Will:                     &awsiot.TopicPayload{Topic: "notification", Payload: "{\"status\": \"dead\"}"},
	// 	OfflineQueueing:          true,
	// 	OfflineQueueMaxSize:      100,
	// 	OfflineQueueDropBehavior: "oldest",
	// 	AutoResubscribe:          true,
	// 	OnConnectionLost: func(opt *awsiot.Options, err error) {
	// 		fmt.Printf("Connection lost handler function called\n")
	// 		newEndpoint, err := ps.PresignWssNow("a3q27gia9qg3zy-ats.iot.us-east-1.amazonaws.com")
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		opt.URL = newEndpoint
	// 	},
	// }

	// // resp, err2 = client.Do(req3)
	// cli := awsiot.New(o)
	// cli.Connect()

	// cli.Subscribe("test", 1, messageHandler)

	// sig := make(chan os.Signal, 1)
	// signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// tick := time.NewTicker(time.Second * 5)

	// for {
	// 	select {
	// 	case <-sig:
	// 		return
	// 	case <-tick.C:
	// 		cli.Publish("notification", 1, false, "{\"status\": \"tick\"}")
	// 	}
	// }

}

func generateChallengeKey() (string, error) {
	p := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, p); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(p), nil
}

func messageHandler(client mqtt.Client, msg mqtt.Message) {
	fmt.Printf("Message received\n")
	fmt.Printf("  topic: %s\n", msg.Topic())
	fmt.Printf("  payload: %s\n", msg.Payload())
}
