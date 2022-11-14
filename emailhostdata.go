package common

import (
	"database/sql"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// ------------------------------------------------------------------------------
// CreateEmailHost - insert an EmailHost
// ------------------------------------------------------------------------------
func CreateEmailHost(s *System, aEmailHost *EmailHost) error {
	// Open a db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()

	// Insert EmailHost, get key
	var vQuery strings.Builder
	vQuery.WriteString("insert into EmailHost(Ehs_Name, Ehs_Port, Ehs_Default, Ehs_User, Ehs_Password)")
	vQuery.WriteString("values(?, ?, ?, ?, ?)")
	res, err := db.Exec(vQuery.String(), aEmailHost.Ehs_Name, aEmailHost.Ehs_Port, aEmailHost.Ehs_Default, aEmailHost.Ehs_User, aEmailHost.Ehs_Password)
	if err != nil {
		return err
	}
	var vKey int64
	vKey, err = res.LastInsertId()
	if vKey == 0 {
		return err
	}
	aEmailHost.Ehs_Key = int(vKey)

	// all ok
	return nil
}

// ------------------------------------------------------------------------------
// ReadEmailHostList - select all EmailHost by filter
// ------------------------------------------------------------------------------
func ReadEmailHostList(s *System, aEmailHostCollection *EmailHostCollection) error {
	// Open db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()
	// Fetch EmailHost rows
	var vQuery strings.Builder
	vQuery.WriteString("select EHS_Key, Ehs_Name, Ehs_Port, Ehs_Default, Ehs_User, Ehs_Password ")
	vQuery.WriteString("from emailhost ")
	vQuery.WriteString("order by Ehs_Default desc, Ehs_Name ")
	// Execute query into rows
	vRows, err := db.Query(vQuery.String())
	if err != nil {
		return err
	}
	// Iterate rows into EmailHostCollection
	defer vRows.Close()
	for vRows.Next() {
		var vEmailHost EmailHost
		if err = vRows.Scan(
			&vEmailHost.Ehs_Key, &vEmailHost.Ehs_Name, &vEmailHost.Ehs_Port, &vEmailHost.Ehs_Default, &vEmailHost.Ehs_User, &vEmailHost.Ehs_Password); err != nil {
			return err
		}
		aEmailHostCollection.List = append(aEmailHostCollection.List, vEmailHost)
	}
	// get any error encountered during iteration
	err = vRows.Err()
	if err != nil {
		return err
	}
	// all ok
	return nil
}

// ------------------------------------------------------------------------------
// ReadEmailHost - select the EmailHost by key
// ------------------------------------------------------------------------------
func ReadEmailHost(s *System, aEmailHost *EmailHost) error {
	// Open db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()
	// Fetch row
	var vQuery strings.Builder
	vQuery.WriteString("select Ehs_Name, Ehs_Port, Ehs_Default, Ehs_User, Ehs_Password  ")
	vQuery.WriteString("from emailhost ")
	vQuery.WriteString("where Ehs_Key = ? ")
	// Execute query into rows
	if err := db.QueryRow(vQuery.String(), &aEmailHost.Ehs_Key).Scan(
		&aEmailHost.Ehs_Name, &aEmailHost.Ehs_Port, &aEmailHost.Ehs_Default, &aEmailHost.Ehs_User, &aEmailHost.Ehs_Password); err != nil {
		return err
	}
	// all ok
	return nil
}

// ------------------------------------------------------------------------------
// ReadEmailHostDefault - select the default EmailHost
// ------------------------------------------------------------------------------
func ReadEmailHostDefault(s *System, aEmailHost *EmailHost) error {
	// Open db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()
	// Fetch row
	var vQuery strings.Builder
	vQuery.WriteString("select Ehs_Name, Ehs_Port, Ehs_Default, Ehs_User, Ehs_Password  ")
	vQuery.WriteString("from emailhost ")
	vQuery.WriteString("where Ehs_Default = true ")
	if err := db.QueryRow(vQuery.String()).Scan(
		&aEmailHost.Ehs_Name, &aEmailHost.Ehs_Port, &aEmailHost.Ehs_Default, &aEmailHost.Ehs_User, &aEmailHost.Ehs_Password); err != nil {
		return err
	}
	// all ok
	return nil
}
