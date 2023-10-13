package repository

import (
	"database/sql"
	"oauth2server/constants"
	"oauth2server/internal/clients"
	"time"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	sqltrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/database/sql"
	gormtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorm.io/gorm.v1"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func InitPGStores() (clientStore *oauth2gorm.ClientStore, tokenStore *oauth2gorm.TokenStore, db *gorm.DB, err error) {
	cfg := &Config{}
	err = envconfig.Process("", cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	//connect database
	var sqlDb *sql.DB
	if cfg.DatadogAgentUrl != "" {
		sqltrace.Register("pgx", &stdlib.Driver{}, sqltrace.WithServiceName("oauth2server"))
		sqlDb, err = sqltrace.Open("pgx", cfg.DatabaseUri)
		if err != nil {
			return nil, nil, nil, err
		}
		db, err = gormtrace.Open(postgres.New(postgres.Config{Conn: sqlDb}), &gorm.Config{})
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		db, err = gorm.Open(postgres.Open(cfg.DatabaseUri), &gorm.Config{})
		if err != nil {
			return nil, nil, nil, err
		}

		sqlDb, err = db.DB()
		if err != nil {
			return nil, nil, nil, err
		}
	}

	sqlDb.SetMaxOpenConns(cfg.DatabaseMaxConns)
	sqlDb.SetMaxIdleConns(cfg.DatabaseMaxIdleConns)
	sqlDb.SetConnMaxLifetime(time.Duration(cfg.DatabaseConnMaxLifetime) * time.Second)

	//migrated from legacy tables
	err = db.Table(constants.ClientTableName).AutoMigrate(&oauth2gorm.ClientStoreItem{})
	if err != nil {
		return nil, nil, nil, err
	}
	err = db.Table(constants.TokenTableName).AutoMigrate(&oauth2gorm.TokenStoreItem{})
	if err != nil {
		return nil, nil, nil, err
	}
	tokenStore = oauth2gorm.NewTokenStoreWithDB(&oauth2gorm.Config{TableName: constants.TokenTableName}, db, constants.GCIntervalSeconds)
	clientStore = oauth2gorm.NewClientStoreWithDB(&oauth2gorm.Config{TableName: constants.ClientTableName}, db)

	//initialize extra db tables
	err = db.AutoMigrate(&clients.ClientMetaData{})
	if err != nil {
		return nil, nil, nil, err
	}

	logrus.Info("Succesfully connected to postgres database")
	return
}
