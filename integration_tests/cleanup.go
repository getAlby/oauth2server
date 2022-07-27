package integrationtests

import (
	"fmt"

	"gorm.io/gorm"
)

func dropTables(db *gorm.DB, tables ...string) error {
	for _, table := range tables {
		err := db.Exec(fmt.Sprintf("delete from %s", table)).Error
		if err != nil {
			return err
		}
	}
	return nil
}
