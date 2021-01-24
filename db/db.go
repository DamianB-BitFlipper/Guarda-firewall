package db

import (
	"fmt"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	log "unknwon.dev/clog/v2"
)

func Init() error {
	d := newDB()
	if d == nil {
		return fmt.Errorf("Unable to create database object")
	}

	// Migrate the databse tables
	if err := autoMigrate(d); err != nil {
		return err
	}

	// Initialize the database accessors
	WebauthnStore = &webauthnStore{DB: d}

	// Success!
	return nil
}

func newDB() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("webauthn-firewall.db"), &gorm.Config{
		// TODO: User `log` module instead of gorm logger
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

func autoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&WebauthnEntry{})
}
