package common

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/smtp"
)

func SendMail(aTemplate string, aData interface{}) error {
	// Cast interface to Register
	vRegister, ok := aData.(*Register)
	if !(ok) {
		return errors.New(fmt.Sprintf("Got data of type %T but wanted int", aData)) // Register assert error
	}

	// Get an Email host
	var vEmailHost = new(EmailHost)
	vEmailHost.Ehs_Key = 1
	vEmailHost.Ehs_Name = "smtp.gmail.com"
	vEmailHost.Ehs_Port = 587
	vEmailHost.Ehs_User = "chatter@zephry.co.za"
	vEmailHost.Ehs_Password = "hy is n regte ou babbelbek"

	host := fmt.Sprintf("%v:%v", vEmailHost.Ehs_Name, vEmailHost.Ehs_Port)
	auth := smtp.PlainAuth("", vEmailHost.Ehs_User, vEmailHost.Ehs_Password, vEmailHost.Ehs_Name)
	to := []string{vRegister.Reg_Email}
	subject := "You have received this from Zephry Estates"

	header := make(map[string]string)
	header["From"] = vEmailHost.Ehs_User
	header["To"] = to[0]
	header["Subject"] = subject
	header["MIME-Version"] = "1.0"
	header["Content-Type"] = fmt.Sprintf("%s; charset=\"utf-8\"", "text/html")
	header["Content-Disposition"] = "inline"
	header["Content-Transfer-Encoding"] = "quoted-printable"

	header_message := ""
	for key, value := range header {
		header_message += fmt.Sprintf("%s: %s\r\n", key, value)
	}

	t, err := template.ParseFiles(fmt.Sprintf("templates/%v", aTemplate))
	if err != nil {
		return err
	}

	buffer := new(bytes.Buffer)
	if err = t.Execute(buffer, aData); err != nil {
		return err
	}
	body := buffer.String()
	msg := header_message + "\r\n" + body

	if err := smtp.SendMail(host, auth, vEmailHost.Ehs_User, to, []byte(msg)); err != nil {
		return err // Unknown smtp error
	}
	return nil
}

func SendMailText(aTo string, aBody string) error {

	// Get an Email host
	var vEmailHost = new(EmailHost)
	vEmailHost.Ehs_Key = 1
	vEmailHost.Ehs_Name = "smtp.gmail.com"
	vEmailHost.Ehs_Port = 587
	vEmailHost.Ehs_User = "chatter@zephry.co.za"
	vEmailHost.Ehs_Password = "hy is n regte ou babbelbek"

	host := fmt.Sprintf("%v:%v", vEmailHost.Ehs_Name, vEmailHost.Ehs_Port)
	auth := smtp.PlainAuth("", vEmailHost.Ehs_User, vEmailHost.Ehs_Password, vEmailHost.Ehs_Name)
	to := []string{aTo}
	subject := "Zephry Estates new registration verification request"

	header := make(map[string]string)
	header["From"] = vEmailHost.Ehs_User
	header["To"] = to[0]
	header["Subject"] = subject
	// header["MIME-Version"]              = "1.0"
	// header["Content-Type"]              = fmt.Sprintf("%s; charset=\"utf-8\"", "text/html")
	// header["Content-Disposition"]       = "inline"
	// header["Content-Transfer-Encoding"] = "quoted-printable"

	header_message := ""
	for key, value := range header {
		header_message += fmt.Sprintf("%s: %s\r\n", key, value)
	}

	msg := header_message + "\r\n" + aBody

	if err := smtp.SendMail(host, auth, vEmailHost.Ehs_User, to, []byte(msg)); err != nil {
		return err // Unknown smtp error
	}
	return nil
}
