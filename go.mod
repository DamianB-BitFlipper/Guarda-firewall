module github.com/JSmith-BitFlipper/webauthn-firewall-proxy

go 1.14

require (
	github.com/cloudflare/cfssl v1.5.0 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/duo-labs/webauthn.io v0.0.0-20200929144140-c031a3e0f95d
	github.com/fxamacker/cbor/v2 v2.2.0 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/sessions v1.2.1
	github.com/jinzhu/gorm v1.9.16
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	gorm.io/driver/sqlite v1.1.4
	gorm.io/gorm v1.20.11
	unknwon.dev/clog/v2 v2.2.0
	webauthn v0.0.0-00010101000000-000000000000
	webauthn_utils v0.0.0-00010101000000-000000000000
)

replace webauthn => ./webauthn

replace webauthn_utils => ./webauthn_utils
