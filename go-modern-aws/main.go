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
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
)

func main() {
	// Load runtime configuration
	c := loadConfig()

	key, err := base64.StdEncoding.DecodeString(c.SecretAppKey)
	if err != nil {
		log.Fatal(err)
	}
	if len(key) <= 0 {
		log.Fatal(`secret application key is unset`)
	}

	http.HandleFunc("/seal", func(w http.ResponseWriter, r *http.Request) {
		var plaintext bytes.Buffer
		defer r.Body.Close()

		// A real implementation should check request Content-Length, validate
		// input size limits, and then only process that much data.
		_, err := io.Copy(&plaintext, r.Body)
		if err != nil {
			log.Println(`400 unable to read request body`)
			w.WriteHeader(400)
			return
		}

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

		ciphertext := aesgcm.Seal(nil, nonce, plaintext.Bytes(), nil)
		fmt.Fprintf(w, "%x:%x", ciphertext, nonce)
	})

	http.HandleFunc("/unseal", func(w http.ResponseWriter, r *http.Request) {
		var envelope bytes.Buffer
		defer r.Body.Close()
		// A real implementation should check request Content-Length, validate
		// input size limits, and then only process that much data.
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

// config will hold all of the application configuration, secret or otherwise.
type config struct {
	// All of these will be loaded from SSM parameters if those parameters are
	// present under a common and specified parameter path.
	SecretAppKey  string `parameter:"secretKey"`
	FavoriteColor string `parameter:"favoriteColor"`
	Locale        string `parameter:"preferences/locale"`

	// The following fields are not tagged with a parameter to be loaded from SSM.
	// the loadConfig() function will not populate it.
	UnmodeledValue1 string `parameter: ""`
	UnmodeledValue2 string
}

var (
	// This application loads and indexes SSM parameters relative to a path.
	iRecursive = true
	// This application requires access to secret data.
	iDecrypt   = true
)

// loadConfig() parses command line flags, enforces input requirements, scrubs
// input for consistency, and loads configuration from AWS Simple System Manager
// service into the applications "config" struct.
//
// Fields are loaded from SSM by "parameter path" where each field on the
// configuration struct is tagged with the path-relative parameter name in SSM.
//
// The path, provided via command line flag, should represent the root of a full
// configuration specification for this application. The path should represent
// a complete namespace and take into consideration all of those things that make
// a specific component deployment unique. Those things typically include
// organization, component, deployment stage, and consistent configuration version.
//
// An example path might look like "/category-team/staging/example-app/2018-8-25.1"
// where "category-team" is the name of the team managing this application, \
// "staging" is the name of the deployment stage where the configuration should be
// used, "example-app" is the name of the application where this code is deployed,
// and 2018-08-25.1 is the consistent version of multi-parameter configuration.
//
// In this example the application will attempt to load three parameters from
// the tree at the specified path: "secretKey," "favoriteColor," and
// "preferences/locale." These parameters are specified as tags in the "config"
// struct.
//
// This code does require that both the config struct field and matching SSM
// parameter are string (or SSM SecureString) types.
//
// SSM will automatically decrypt SecureString parameters if the identity used
// to retrive the SSM parameters has access to the KMS key used to encrypt each
// parameter.
func loadConfig() *config {
	appConfigPath := flag.String(`config-path`, `example-app`, `Provide the SSM parameter path for this application's configuration.`)
	flag.Parse()
	if appConfigPath == nil || len(*appConfigPath) <= 0 {
		fmt.Println(`-path must be specified`)
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Make sure that the specified path ends with a trailing slash.
	// Append one otherwise.
	if (*appConfigPath)[len(*appConfigPath)-1] != byte('/') {
		*appConfigPath += `/`
	}

	// Load all of the configuration parameters at and below the specified
	// path from SSM parameter store.
	// Index those parameters by name for mapping into local config object.
	rc := map[string]ssm.Parameter{}
	// Create AWS client with infrastructure secret material.
	// session.NewSession() uses the default AWS SDK credential chain.
	sess := session.Must(session.NewSession())
	svc := ssm.New(sess)
	var po *ssm.GetParametersByPathOutput
	pi := &ssm.GetParametersByPathInput{
		Path:           appConfigPath,
		Recursive:      &iRecursive,
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
			rc[strings.TrimPrefix(*p.Name, *appConfigPath)] = *p
		}
		if po.NextToken == nil {
			break
		}
	}

	// Iterate on the config object fields and populate by tag reflection.
	c := config{}
	st := reflect.TypeOf(c)
	sv := reflect.ValueOf(&c).Elem()
	for i := 0; i < st.NumField(); i++ {
		ft := st.Field(i)
		fv := sv.Field(i)

		// Verify that the field has a populated "parameter" tag
		tv := ft.Tag.Get(`parameter`)
		if len(tv) <= 0 {
			log.Printf("Field %s is not annotated\n", ft.Name)
			continue
		}
		// Verify that the tagged parameter is included in the
		// retrieved configuration
		cv, ok := rc[tv]
		if !ok {
			log.Printf("Parameter %s is not included in the retrievd configuration\n", tv)
			continue
		}
		// Verify that both the field and parameter are string types.
		// If they are not then log the types.
		if ft.Type.Kind() == reflect.String && *cv.Type == `String` || *cv.Type == `SecureString` {
			log.Printf("Setting field %s with value %s\n", ft.Name, *cv.Value)
			fv.SetString(*cv.Value)
		} else {
			log.Printf("Ignoring configuration field %s of type %s. Is not string or does not match named parameter %s of type %s.\n",
				ft.Name,
				ft.Type.Name,
				tv,
				cv.Type,
			)
		}
	}

	return &c
}
