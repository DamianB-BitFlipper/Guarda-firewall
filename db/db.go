package db

import (
	"context"
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

// Create a logger interface for the `log` library
type dbLogger struct {
	logLevel      logger.LogLevel
	slowThreshold time.Duration
}

var _ logger.Interface = (*dbLogger)(nil)

var (
	defaultLogger = &dbLogger{
		logLevel:      logger.Warn,
		slowThreshold: 200 * time.Millisecond,
	}
)

func (l *dbLogger) LogMode(level logger.LogLevel) logger.Interface {
	newLogger := *l
	newLogger.logLevel = level
	return &newLogger
}

func (l dbLogger) Info(_ context.Context, msg string, data ...interface{}) {
	if l.logLevel >= logger.Info {
		//log.Info(msg, append([]interface{}{utils.FileWithLineNum()}, data...)...)
		log.Info(msg, data...)
	}
}

func (l dbLogger) Warn(_ context.Context, msg string, data ...interface{}) {
	if l.logLevel >= logger.Warn {
		//log.Info(msg, append([]interface{}{utils.FileWithLineNum()}, data...)...)
		log.Warn(msg, data...)
	}
}

func (l dbLogger) Error(_ context.Context, msg string, data ...interface{}) {
	if l.logLevel >= logger.Error {
		//log.Info(msg, append([]interface{}{utils.FileWithLineNum()}, data...)...)
		log.Error(msg, data...)
	}
}

// Trace print sql message
func (l dbLogger) Trace(_ context.Context, begin time.Time, fc func() (string, int64), err error) {
	var (
		traceStr     = "[%.3fms] [rows:%v] %s"
		traceWarnStr = "%s [%.3fms] [rows:%v] %s"
		traceErrStr  = "%s [%.3fms] [rows:%v] %s"
	)

	if l.logLevel > logger.Silent {
		elapsed := time.Since(begin)
		switch {
		case err != nil && l.logLevel >= logger.Error:
			sql, rows := fc()
			if rows == -1 {
				log.Error(traceErrStr, err.Error(), float64(elapsed.Nanoseconds())/1e6, "-", sql)
			} else {
				log.Error(traceErrStr, err.Error(), float64(elapsed.Nanoseconds())/1e6, rows, sql)
			}
		case elapsed > l.slowThreshold && l.slowThreshold != 0 && l.logLevel >= logger.Warn:
			sql, rows := fc()
			slowLog := fmt.Sprintf("SLOW SQL >= %v", l.slowThreshold)
			if rows == -1 {
				log.Warn(traceWarnStr, slowLog, float64(elapsed.Nanoseconds())/1e6, "-", sql)
			} else {
				log.Warn(traceWarnStr, slowLog, float64(elapsed.Nanoseconds())/1e6, rows, sql)
			}
		case l.logLevel == logger.Info:
			sql, rows := fc()
			if rows == -1 {
				log.Info(traceStr, float64(elapsed.Nanoseconds())/1e6, "-", sql)
			} else {
				log.Info(traceStr, float64(elapsed.Nanoseconds())/1e6, rows, sql)
			}
		}
	}
}

func newDB() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("webauthn-firewall.db"), &gorm.Config{
		Logger: defaultLogger,
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
