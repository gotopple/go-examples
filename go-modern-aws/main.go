package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
)

func main() {
	// Load runtime configuration
	c := loadConfig()

	key, err := base64.StdEncoding.DecodeString(c.secretAppKey)
	if err != nil {
		log.Fatal(err)
	}
	if len(key) <= 0 {
		log.Fatal(`secret application key is unset`)
	}

	http.HandleFunc("/seal", func(w http.ResponseWriter, r *http.Request){
		plaintext := []byte(`hello world`)
		block, err := aes.NewCipher(key)
		if err != nil {
			log.Fatal(err)
		}

		nonce := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			panic(err.Error())
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err.Error())
		}

		ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
		fmt.Fprintf(w, "%x:%x", ciphertext, nonce)
	})

	http.HandleFunc("/unseal", func(w http.ResponseWriter, r *http.Request) {
		var envelope bytes.Buffer
		defer r.Body.Close()
		_, err := io.Copy(&envelope, r.Body)
		if err != nil {
			panic(err.Error())
		}
		parts := strings.Split(envelope.String(), `:`)
		if len(parts) != 2 {
			panic(`invalid input envelope`)
		}
		ciphertext, err := hex.DecodeString(parts[0])
		nonce, err := hex.DecodeString(parts[1])
		if err != nil {
			panic(`invalid input envelope`)
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err.Error())
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err.Error())
		}

		plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			panic(err.Error())
		}

		fmt.Fprintf(w, "%s\n", plaintext)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}

type config struct {
	secretAppKey string
}

var (
	iRecursive = true
	iDecrypt = true
)

func loadConfig() *config {
	appSecretParameterPath := flag.String(`path`, `example-app`, `Provide the SSM parameter path for this application's configuration.`)
	flag.Parse()
	if appSecretParameterPath == nil || len(*appSecretParameterPath) <= 0 {
		fmt.Println(`-path must be specified`)
		flag.PrintDefaults()
		os.Exit(1)
	}

	c := &config{}

	// Create AWS client with infrastructure secret material.
	// session.NewSession() uses the default AWS SDK credential chain.
	sess := session.Must(session.NewSession())
	svc := ssm.New(sess)
	var po *ssm.GetParametersByPathOutput
	pi := &ssm.GetParametersByPathInput{
		Path: appSecretParameterPath,
		Recursive: &iRecursive,
		WithDecryption: &iDecrypt,
	}
	for {
		if po != nil {
			pi.NextToken = po.NextToken
		}
		po, err := svc.GetParametersByPath(pi)
		if err != nil {
			log.Fatal(err)
		}

		for _, p := range po.Parameters {
			switch *p.Name {
			case `secret-key`:
				c.secretAppKey = *p.Value
			default:
				// ignoring unknown parameters - could be used by future versions
			}
		}
		if po.NextToken == nil {
			break
		}
	}

	return c
}
