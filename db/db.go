package db

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	log "unknwon.dev/clog/v2"
)

func New() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("webauthn-firewall.db"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
		NowFunc: func() time.Time {
			return time.Now().Local()
		},
	})
	if err != nil {
		log.Error("Storage err: %v", err)
		return nil
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Error("Storage err: %v", err)
		return nil
	}

	sqlDB.SetMaxIdleConns(3)
	return db
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&WebauthnEntry{})
}
