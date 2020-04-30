package help

import "github.com/taiyuechain/taiyuechain/log"

func CheckAndPrintError(err error) {
	if err != nil {
		log.Debug("CheckAndPrintError", "error", err.Error())
	}
}
