package common

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"text/template"

	_ "github.com/go-sql-driver/mysql"
)

// ------------------------------------------------------------------
// Check whether a register already exists for email
// ------------------------------------------------------------------
func CheckRegister(s *System, aRegister *Register) error {
	// Open a db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()

	// Check register
	var vCount int
	var vQuery strings.Builder
	vQuery.WriteString("select count(*) ")
	vQuery.WriteString("from register ")
	vQuery.WriteString("where Reg_Email = ? ")
	err = db.QueryRow(vQuery.String(), aRegister.Reg_Email).Scan(&vCount)
	if err != nil {
		return err // Unknown db error
	}
	if vCount > 0 {
		return errors.New("Account already registered")
	}

	return nil // All good
}

// ------------------------------------------------------------------
// Create a register, send a message
// ------------------------------------------------------------------
func CreateRegister(s *System, aRegister *Register) error {
	// Open a db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()

	// Insert register
	var vKey int64
	var vQuery strings.Builder
	vQuery.WriteString("insert into register(Reg_Name, Reg_Surname, Reg_Email, Reg_Password, Reg_Token, Reg_Date)")
	vQuery.WriteString("values(?, ?, ?, ?, uuid(), now())")
	res, err := db.Exec(vQuery.String(), aRegister.Reg_Name, aRegister.Reg_Surname, aRegister.Reg_Email, aRegister.Reg_Password)
	if err != nil {
		return err // Unknown db error
	}
	vKey, err = res.LastInsertId()
	if vKey == 0 {
		return err // Unknown db error
	}
	aRegister.Reg_Key = int(vKey)

	// Get the generated token/date, build a link string
	vQuery.Reset()
	vQuery.WriteString("select Reg_Token, Reg_Date ")
	vQuery.WriteString("from register ")
	vQuery.WriteString("where Reg_Key = ? ")
	err = db.QueryRow(vQuery.String(), aRegister.Reg_Key).Scan(&aRegister.Reg_Token, &aRegister.Reg_Date)
	if err != nil {
		return err // Unknown db error
	}
	var vSDate = fmt.Sprintf("%d%02d%02d%02d%02d%02d",
		aRegister.Reg_Date.Year(), aRegister.Reg_Date.Month(), aRegister.Reg_Date.Day(),
		aRegister.Reg_Date.Hour(), aRegister.Reg_Date.Minute(), aRegister.Reg_Date.Second())
	aRegister.Reg_Passthru = fmt.Sprintf("%v?dte=%v&tkn=%v&key=%v", aRegister.Reg_Passthru, vSDate, aRegister.Reg_Token, aRegister.Reg_Key)

	// Parse the verify template, pass to sendmail as body
	t, err := template.ParseFiles(fmt.Sprintf("templates/%v", "register.text"))
	if err != nil {
		return err
	}

	buffer := new(bytes.Buffer)
	if err = t.Execute(buffer, aRegister); err != nil {
		return err
	}
	// Send a register verify email
	// err = SendMailText(aRegister.Reg_Email, buffer.String())
	// if err != nil {
	// 	return err // Unknown mail error
	// }

	return nil // All good
}

// ------------------------------------------------------------------
// Read a Register with key
// ------------------------------------------------------------------
func ReadRegister(s *System, aRegister *Register) error {
	// Open a db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()

	// Test register
	var vQuery strings.Builder
	vQuery.WriteString("select Reg_Key, Reg_Name, Reg_Surname, Reg_Email, Reg_Password, Reg_Token, Reg_Date ")
	vQuery.WriteString("from register ")
	vQuery.WriteString("where Reg_Key = ? ")
	if err := db.QueryRow(vQuery.String(), aRegister.Reg_Key).Scan(
		&aRegister.Reg_Key, &aRegister.Reg_Name, &aRegister.Reg_Surname, &aRegister.Reg_Email, &aRegister.Reg_Password,
		&aRegister.Reg_Token, &aRegister.Reg_Date); err != nil {
		return err // Unknown db error
	}

	return nil // All good
}

// ------------------------------------------------------------------
// Check whether a user already exists for email
// ------------------------------------------------------------------
func CheckUser(s *System, aUser *User) (bool, error) {
	// Open a db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return false, err
	}
	defer db.Close()

	// Check user
	var vCount int
	var vQuery strings.Builder
	vQuery.WriteString("select Usr_Key, count(*) ")
	vQuery.WriteString("from user ")
	vQuery.WriteString("where Usr_Email = ? ")
	vQuery.WriteString("group by Usr_Key ")
	if err = db.QueryRow(vQuery.String(), aUser.Usr_Email).Scan(&aUser.Usr_Key, &vCount); err != nil {
		if err == sql.ErrNoRows {
			return false, nil // User not found
		} else {
			return false, err // Unknown db error
		}
	}

	if vCount > 1 {
		return false, fmt.Errorf("System Exception! User anomoly for user '%v'", aUser.Usr_Email) // More than 1 user with same email - disaster!!!
	}

	return true, nil // Exactly 1 user found
}

// ------------------------------------------------------------------
// MergeUserRegister - Create a user, delete a register, in a transaction
// ------------------------------------------------------------------
func MergeUserRegister(s *System, aUser *User) error {
	// Open a db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()

	// Create a transaction
	tx, err := db.Begin()
	if err != nil {
		return err // Unknown db error
	}

	// Insert user
	var vKey int64
	var vQuery strings.Builder
	vQuery.WriteString("insert into user(Usr_Name, Usr_Surname, Usr_Email, Usr_Password, Usr_Identity, Usr_Token, Usr_Date)")
	vQuery.WriteString("values(?, ?, ?, ?, ?, ?, now())")
	res, err := tx.Exec(vQuery.String(), aUser.Usr_Name, aUser.Usr_Surname, aUser.Usr_Email, aUser.Usr_Password, aUser.Usr_Identity, aUser.Usr_Token)
	if err != nil {
		tx.Rollback()
		return err // Unknown db error
	}
	vKey, err = res.LastInsertId()
	if vKey == 0 {
		tx.Rollback()
		return err // Unknown db error
	}
	aUser.Usr_Key = int(vKey)

	// Delete the Register
	vQuery.Reset()
	vQuery.WriteString("delete from register where Reg_Email = ?")
	_, err = tx.Exec(vQuery.String(), aUser.Usr_Email)
	if err != nil {
		tx.Rollback()
		return err // Unknown db error
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		return err // Unknown db error
	}

	// All good
	return nil
}

// ------------------------------------------------------------------
// Get a User of Key, return the User's Token
// ------------------------------------------------------------------
func Authenticate(s *System, aToken *Token) error {
	// Open a db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()
	// Create a token placeholder and fetch a user token
	var vToken string = ""
	var vQuery strings.Builder
	vQuery.WriteString("select Usr_Token ")
	vQuery.WriteString("from user ")
	vQuery.WriteString("where Usr_Key = ? ")
	err = db.QueryRow(vQuery.String(), aToken.Key).Scan(&vToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("invalid user") // User not found
		} else {
			return err // Unknown db error
		}
	}
	if vToken != aToken.Token {
		return errors.New("invalid user/token") // User/Token mismatch
	}
	return nil // All good
}

// ------------------------------------------------------------------
// Get user access to route
// ------------------------------------------------------------------
func Authorize(s *System, aRoute string, aMethod string) error {
	// Open a db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()
	// Create a token placeholder and fetch a user token
	var vCount int = 0
	var vQuery strings.Builder
	vQuery.WriteString("select count(*) ")
	vQuery.WriteString("from route ")
	vQuery.WriteString("where ? REGEXP Rte_Regex ")
	vQuery.WriteString("and   Rte_Method = ? ")
	err = db.QueryRow(vQuery.String(), aRoute, aMethod).Scan(&vCount)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New(fmt.Sprintf("User not authorized for %s %s", aMethod, aRoute)) // User not found
		} else {
			return err // Unknown db error
		}
	}
	if vCount == 0 {
		return errors.New("User not authorized")
	}
	return nil // All good
}

// ------------------------------------------------------------------
// Get a Usr_Key and Usr_Token with Login details
// ------------------------------------------------------------------
func getKeyToken(s *System, aLogin *Login) (int, string, error) {
	// Open a db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return 0, "", err
	}
	defer db.Close()
	// Create a key and an Account
	var vUsrKey int
	var vToken string
	var vQuery strings.Builder
	// Update the GUID of a User with a matching auth set of UserID and Password
	vQuery.WriteString("update user set Usr_Token = uuid() ")
	vQuery.WriteString("where Usr_Email = ? ")
	vQuery.WriteString("and   Usr_Password = ? ")
	res, err := db.Exec(vQuery.String(), aLogin.Email, aLogin.Token)
	if err != nil {
		return 0, "", err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, "", err
	}
	if affected == 0 {
		return 0, "", errors.New("")
	}
	// Then return the GUID
	vQuery.Reset()
	vQuery.WriteString("select Usr_Key, Usr_Token ")
	vQuery.WriteString("from user ")
	vQuery.WriteString("where Usr_Email = ? ")
	vQuery.WriteString("and   Usr_Password = ? ")
	err = db.QueryRow(vQuery.String(), aLogin.Email, aLogin.Token).Scan(&vUsrKey, &vToken)
	if err != nil {
		return 0, "", err
	}
	return vUsrKey, vToken, nil
}

// ------------------------------------------------------------------
// Create a forgot, send a message
// ------------------------------------------------------------------
func CreateForgot(s *System, aForgot *Forgot) error {
	// only create a Forgot for verification if a user exists
	if aForgot.Fgt_Exists {
		// Open a db, defer close
		db, err := sql.Open("mysql", s.SqlString())
		if err != nil {
			return err
		}
		defer db.Close()

		// Insert forgot
		var vKey int64
		var vQuery strings.Builder
		vQuery.WriteString("insert into forgot(Fgt_Email, Fgt_Token, Fgt_Date)")
		vQuery.WriteString("values(?, uuid(), now())")
		res, err := db.Exec(vQuery.String(), aForgot.Fgt_Email)
		if err != nil {
			return err // Unknown db error
		}
		vKey, err = res.LastInsertId()
		if vKey == 0 {
			return err // Unknown db error
		}
		aForgot.Fgt_Key = int(vKey)

		// Get the generated token/date, build a link string
		vQuery.Reset()
		vQuery.WriteString("select Fgt_Token, Fgt_Date ")
		vQuery.WriteString("from forgot ")
		vQuery.WriteString("where Fgt_Key = ? ")
		err = db.QueryRow(vQuery.String(), aForgot.Fgt_Key).Scan(&aForgot.Fgt_Token, &aForgot.Fgt_Date)
		if err != nil {
			return err // Unknown db error
		}
		aForgot.Fgt_Passthru = fmt.Sprintf("%v?tkn=%v&key=%v", aForgot.Fgt_Passthru, aForgot.Fgt_Token, aForgot.Fgt_Key)
	}
	// Send an email whether a user exists or not.
	// Parse the verify template, pass to sendmail as body
	t, err := template.ParseFiles(fmt.Sprintf("templates/%v", "forgot.text"))
	if err != nil {
		return err
	}

	buffer := new(bytes.Buffer)
	if err = t.Execute(buffer, aForgot); err != nil {
		return err
	}
	// Send a forgot verify email
	err = SendMailText(aForgot.Fgt_Email, buffer.String())
	if err != nil {
		return err // Unknown mail error
	}

	return nil // All good
}

// ------------------------------------------------------------------
// Read a Forgot with key
// ------------------------------------------------------------------
func ReadForgot(s *System, aForgot *Forgot) error {
	// Open a db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()

	// Test register
	var vQuery strings.Builder
	vQuery.WriteString("select Fgt_Email, Fgt_Token, Fgt_Date ")
	vQuery.WriteString("from forgot ")
	vQuery.WriteString("where Fgt_Key = ? ")
	if err := db.QueryRow(vQuery.String(), aForgot.Fgt_Key).Scan(
		&aForgot.Fgt_Email, &aForgot.Fgt_Token, &aForgot.Fgt_Date); err != nil {
		return err // Unknown db error
	}

	return nil // All good
}

// ------------------------------------------------------------------
// MergeUserForgot - Create a user, delete a forgot, in a transaction
// ------------------------------------------------------------------
func MergeUserForgot(s *System, aUser *User) error {
	// Open a db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()

	// Create a transaction
	tx, err := db.Begin()
	if err != nil {
		return err // Unknown db error
	}

	// Update user
	var vQuery strings.Builder
	vQuery.WriteString("update user set Usr_Password = ? ")
	vQuery.WriteString("where Usr_Key = ?")
	res, err := tx.Exec(vQuery.String(), aUser.Usr_Password, aUser.Usr_Key)
	if err != nil {
		tx.Rollback()
		return err // Unknown db error
	}

	vAffected, _ := res.RowsAffected()
	if vAffected != 1 {
		return errors.New(fmt.Sprintf("System Exception! Password wants to update multiple users for email '%v'", aUser.Usr_Email)) // More than 1 user with same email - disaster!!!
	}

	// Delete the Forgot
	vQuery.Reset()
	vQuery.WriteString("delete from forgot where Fgt_Email = ?")
	_, err = tx.Exec(vQuery.String(), aUser.Usr_Email)
	if err != nil {
		tx.Rollback()
		return err // Unknown db error
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		return err // Unknown db error
	}

	// All good
	return nil
}

// ------------------------------------------------------------------------------
// Update User Avatar
// ------------------------------------------------------------------------------
func ReadUserAvatar(s *System, aUserAvatar *UserAvatar) error {
	// Open db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()

	// Read
	var vQuery strings.Builder
	vQuery.WriteString("select Usr_Avatar, ifnull(Usr_Extension, \"png\") as Usr_Extension ")
	vQuery.WriteString("from user ")
	vQuery.WriteString("where Usr_Key = ? ")
	if err := db.QueryRow(vQuery.String(), &aUserAvatar.Usr_Key).Scan(&aUserAvatar.Usr_Avatar, &aUserAvatar.Usr_Extension); err != nil {
		return err
	}
	return nil
}

// ------------------------------------------------------------------------------
// Update User Avatar
// ------------------------------------------------------------------------------
func UpdateUserAvatar(s *System, aUserAvatar *UserAvatar) error {
	// Open db, defer close
	db, err := sql.Open("mysql", s.SqlString())
	if err != nil {
		return err
	}
	defer db.Close()

	// Read
	var vQuery strings.Builder
	vQuery.WriteString("update user set Usr_Extension = ? where Usr_Key = ? ")
	if err := db.QueryRow(vQuery.String(), &aUserAvatar.Usr_Key).Scan(&aUserAvatar.Usr_Extension, &aUserAvatar.Usr_Key); err != nil {
		return err
	}
	return nil
}
