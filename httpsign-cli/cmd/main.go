package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli"

	"github.com/KyberNetwork/httpsign-utils/sign"
)

func main() {
	app := cli.NewApp()
	app.Name = "HTTP Signatures cli client. This command accepts similar flags as cURL."
	app.Action = run
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "user, u",
			Usage:  "specify the key pair (access:secret) to use for server authentication",
			EnvVar: "ACCESS_KEY_PAIR",
		},
		cli.StringFlag{
			Name:  "request, X",
			Usage: "HTTP request method to use",
			Value: http.MethodGet,
		},
		cli.StringFlag{
			Name:  "data, d",
			Usage: "data to send to HTTP Server with application/json content type",
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func parseKeyPair(keyPair string) (accessKeyID string, secretAccessKey string, err error) {
	if len(keyPair) == 0 {
		return "", "", errors.New("missing access key keyPair")
	}
	keys := strings.Split(keyPair, ":")
	if len(keys) != 2 {
		return "", "", errors.New("invalid key pair format")
	}
	if len(keys[0]) == 0 {
		return "", "", errors.New("missing access key id")
	}
	if len(keys[1]) == 0 {
		return "", "", errors.New("missing secret access key")
	}
	return keys[0], keys[1], nil
}

func run(c *cli.Context) error {
	var (
		url     = c.Args().First()
		method  = strings.ToUpper(c.String("request"))
		keyPair = c.String("user")
		data    = c.String("data")
		body    io.Reader
	)

	if len(url) == 0 {
		return errors.New("missing URL")
	}

	accessKeyID, secretKeyID, err := parseKeyPair(keyPair)
	if err != nil {
		return err
	}

	if len(data) != 0 {
		body = strings.NewReader(data)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}

	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete:
		req.Header.Add("Content-Type", "application/json")
	case http.MethodGet:
	default:
		return fmt.Errorf("invalid method %s", method)
	}

	req, err = sign.Sign(req, accessKeyID, secretKeyID)
	if err != nil {
		return err
	}

	client := http.Client{
		Timeout: time.Minute,
	}

	rsp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		if cErr := rsp.Body.Close(); cErr != nil {
			log.Printf("failed to close body: %s", cErr.Error())
		}
	}()

	if rsp.StatusCode > 400 {
		return fmt.Errorf("unexpected status: %s", rsp.Status)
	}

	output, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return err
	}

	fmt.Print(string(output))

	return rsp.Body.Close()
}
