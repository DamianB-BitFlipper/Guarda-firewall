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
	UserID      int64     `gorm:"unique_index;not null"`
	Username    string    `gorm:"unique_index;not null"`
	Created     time.Time `gorm:"-"`
	CreatedUnix int64

	// Webauthn entries
	PubKey    []byte `gorm:"type:varchar(65);unique"`
	CredID    []byte `gorm:"type:varchar(250);unique"`
	SignCount uint32 `gorm:"default:0"`
	RPID      string `gorm:"column:rp_id;type:varchar(253)"`
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

type webauthnQuery func(*webauthnStore) *gorm.DB

var WebauthnStore *webauthnStore

func QueryByUserID(userID int64) webauthnQuery {
	return func(db *webauthnStore) *gorm.DB {
		return db.Model(new(WebauthnEntry)).Where("user_id = ?", userID)
	}
}

func QueryByUsername(username string) webauthnQuery {
	return func(db *webauthnStore) *gorm.DB {
		return db.Model(new(WebauthnEntry)).Where("username = ?", username)
	}
}

func (db *webauthnStore) Create(wuser webauthnUser, credential *webauthn.Credential) error {
	wentry := &WebauthnEntry{
		UserID:    wuser.userID,
		Username:  wuser.username,
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

func (db *webauthnStore) numCredentials(query webauthnQuery) int64 {
	var count int64
	err := query(db).Count(&count).Error
	if err != nil {
		log.Error("Failed to count webauthn entries: %v", err)
		return 0
	}
	return count
}

func (db *webauthnStore) getCredentials(query webauthnQuery) (*WebauthnEntry, error) {
	ncreds := db.numCredentials(query)
	if ncreds == 0 {
		return nil, nil
	}

	entry := new(WebauthnEntry)

	err := query(db).First(&entry).Error
	if err != nil {
		log.Error("Failed to get webauthn entries: %v", err)
		return nil, err
	}

	return entry, nil
}

func (db *webauthnStore) IsUserEnabled(query webauthnQuery) bool {
	return db.numCredentials(query) > 0
}

func (db *webauthnStore) GetWebauthnUser(query webauthnQuery) (webauthnUser, error) {
	// Get the webauthn entry corresponding to the input `webauthnQuery`
	entry, err := WebauthnStore.getCredentials(query)
	if entry == nil || err != nil {
		return webauthnUser{}, err
	}

	// Create a new `webauthnUser`
	w := NewWebauthnUser(entry.UserID, entry.Username, nil)

	// Rebuild the `credential` from the `entry`
	var credential webauthn.Credential
	credential.ID = entry.CredID
	credential.PublicKey = entry.PubKey
	credential.Authenticator = webauthn.Authenticator{SignCount: entry.SignCount}

	// Set the `credential` into the `webauthnUser`
	w.credentials = []webauthn.Credential{credential}

	return w, nil
}
