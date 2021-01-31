package db

import (
	"time"

	"gorm.io/gorm"
	log "unknwon.dev/clog/v2"

	"webauthn/webauthn"
)

type WebauthnEntry struct {
	gorm.Model
	// Metadata entries
	ID          int64     `gorm:"PRIMARYKEY"`
	Username    string    `gorm:"UNIQUE;NOT NULL"` // TODO: Golang GORM sets deleted_at, so re-registering user will fail unique condition
	Created     time.Time `gorm:"-"`
	CreatedUnix int64

	// Webauthn entries
	PubKey    []byte `gorm:"TYPE:VARCHAR(65);UNIQUE"`
	CredID    []byte `gorm:"TYPE:VARCHAR(250);UNIQUE"`
	SignCount uint32 `gorm:"DEFAULT:0"`
	RPID      string `gorm:"COLUMN:rp_id;TYPE:VARCHAR(253)"`
}

// NOTE: This is a GORM create hook.
func (t *WebauthnEntry) BeforeCreate(tx *gorm.DB) error {
	if t.CreatedUnix == 0 {
		t.CreatedUnix = tx.NowFunc().Unix()
	}
	return nil
}

// NOTE: This is a GORM query hook.
func (t *WebauthnEntry) AfterFind(tx *gorm.DB) error {
	t.Created = time.Unix(t.CreatedUnix, 0).Local()
	return nil
}

//
// `WebauthnEntry` storage methods
//

type webauthnStore struct {
	*gorm.DB
}

var WebauthnStore *webauthnStore

func (db *webauthnStore) Create(username string, credential webauthn.Credential) error {
	wentry := &WebauthnEntry{
		Username:  username,
		PubKey:    credential.PublicKey,
		CredID:    credential.ID,
		SignCount: credential.Authenticator.SignCount,
		RPID:      "TODO",
	}

	return db.DB.Create(&wentry).Error
}

func (db *webauthnStore) Delete(username string) (err error) {
	err = db.Model(new(WebauthnEntry)).Where("username = ?", username).Delete(new(WebauthnEntry)).Error
	if err != nil {
		log.Error("Failed to delete webauthn entry [username: %s]: %v", username, err)
	}
	return
}

func (db *webauthnStore) numCredentials(username string) (count int64) {
	err := db.Model(new(WebauthnEntry)).Where("username = ?", username).Count(&count).Error
	if err != nil {
		log.Error("Failed to count webauthn entries [username: %d]: %v", username, err)
		return 0
	}
	return
}

func (db *webauthnStore) getCredentials(username string) (*WebauthnEntry, error) {
	ncreds := db.numCredentials(username)
	if ncreds == 0 {
		return nil, nil
	}

	entry := new(WebauthnEntry)

	err := db.Model(new(WebauthnEntry)).Where("username = ?", username).First(&entry).Error
	if err != nil {
		log.Error("Failed to get webauthn entries [username: %d]: %v", username, err)
		return nil, err
	}

	return entry, nil
}

func (db *webauthnStore) IsUserEnabled(username string) bool {
	return db.numCredentials(username) > 0
}

func (db *webauthnStore) GetWebauthnUser(username string) (webauthnUser, error) {
	// Get the webauthn entry corresponding to the input `username`
	entry, err := WebauthnStore.getCredentials(username)
	if err != nil {
		return webauthnUser{}, err
	}

	w := webauthnUser{
		username:    username,
		credentials: nil,
	}

	// If there is not a webauthn credential yet, return as is
	if entry == nil {
		return w, nil
	}

	// Rebuild the `credential` from the `entry`
	var credential webauthn.Credential
	credential.ID = entry.CredID
	credential.PublicKey = entry.PubKey
	credential.Authenticator = webauthn.Authenticator{SignCount: entry.SignCount}

	// Set the `credential` into the `webauthnUser`
	w.credentials = []webauthn.Credential{credential}

	return w, nil
}
