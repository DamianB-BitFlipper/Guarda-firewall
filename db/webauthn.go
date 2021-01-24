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
	Username    string    `gorm:"UNIQUE;NOT NULL"`
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

func (db *webauthnStore) numCredentials(username string) (count int64) {
	err := db.Model(new(WebauthnEntry)).Where("username = ?", username).Count(&count).Error
	if err != nil {
		log.Error("Failed to count webauthn entries [username: %d]: %v", username, err)
	}
	return count
}

func (db *webauthnStore) getCredentials(username string) ([]*WebauthnEntry, error) {
	ncreds := db.numCredentials(username)
	entries := make([]*WebauthnEntry, 0, ncreds)

	err := db.Model(new(WebauthnEntry)).Where("username = ?", username).Find(&entries).Error
	if err != nil {
		log.Error("Failed to get webauthn entries [username: %d]: %v", username, err)
		return []*WebauthnEntry{}, err
	}

	return entries, nil
}

func (db *webauthnStore) GetWebauthnUser(username string) (webauthnUser, error) {
	// Convert the slice of `WebauthnEntry` to `webauthn.Credential`
	entries, err := WebauthnStore.getCredentials(username)
	if err != nil {
		return webauthnUser{}, err
	}

	credentials := make([]webauthn.Credential, 0, len(entries))

	for _, entry := range entries {
		// Rebuild the `credential` from the `entry`
		var credential webauthn.Credential
		credential.ID = entry.CredID
		credential.PublicKey = entry.PubKey
		credential.Authenticator = webauthn.Authenticator{SignCount: entry.SignCount}

		// Append `credential` to the `credentials` slice
		credentials = append(credentials, credential)
	}

	// TODO: I need to differentiate webauthn user ID and webauthn credential entries
	// Why are the multiple credential entries per user, seems redundant and dumb
	w := webauthnUser{
		userID:      69420, // TODO
		username:    username,
		credentials: credentials,
	}
	return w, nil
}
