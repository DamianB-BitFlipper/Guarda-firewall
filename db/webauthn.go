package db

import (
	"time"

	"gorm.io/gorm"

	"webauthn/webauthn"
)

type WebauthnEntry struct {
	gorm.Model
	UserID      int64     `gorm:"UNIQUE"`
	Created     time.Time `gorm:"-"`
	CreatedUnix int64

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

type WebauthnStore struct {
	*gorm.DB
}

func (db *WebauthnStore) Create(userID int64, credential webauthn.Credential) error {
	wentry := &WebauthnEntry{
		UserID:    userID,
		PubKey:    credential.PublicKey,
		CredID:    credential.ID,
		SignCount: credential.Authenticator.SignCount,
		RPID:      "TODO",
	}

	return db.DB.Create(&wentry).Error
}
