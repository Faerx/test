package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	errorL = log.New(os.Stderr, "ERROR: ", log.LstdFlags|log.Lshortfile)
	warnL  = log.New(os.Stderr, "EWARN: ", log.LstdFlags)
	infoL  = log.New(os.Stderr, "INFO: ", log.LstdFlags)
)

func HaltOnError(err error, msgs ...string) {
	if err == nil {
		return
	}
	msg := "Error occured"
	if len(msgs) > 0 {
		msg = fmt.Sprint("%s: %s", msg, strings.Join(msgs, " "))
	}
	errorL.Printf("%s: %v", msg, err)
	os.Exit(1)
}

func Info(msg string) {
	infoL.Println(msg)
}
func Warn(err error, msgs ...string) {
	if err != nil {
		msg := "Warning occured"
		if len(msgs) > 0 {
			msg = fmt.Sprint("%s: %s", msg, strings.Join(msgs, " "))
		}
		warnL.Printf("%s: %v", msg, err)
	}
}
