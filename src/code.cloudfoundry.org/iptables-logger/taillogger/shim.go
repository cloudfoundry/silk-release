package taillogger

import (
	"fmt"

	"code.cloudfoundry.org/lager/v3"
)

type Shim struct {
	lager.Logger
}

func (s Shim) Fatal(v ...interface{}) {
	s.Logger.Fatal("fatal", nil, lager.Data{"message": fmt.Sprint(v...)})
}

func (s Shim) Fatalf(format string, v ...interface{}) {
	s.Logger.Fatal("fatal", nil, lager.Data{"message": fmt.Sprintf(format, v...)})
}

func (s Shim) Fatalln(v ...interface{}) {
	s.Logger.Fatal("fatal", nil, lager.Data{"message": fmt.Sprintln(v...)})
}

func (s Shim) Panic(v ...interface{}) {
	s.Logger.Fatal("panic", nil, lager.Data{"message": fmt.Sprint(v...)})
}

func (s Shim) Panicf(format string, v ...interface{}) {
	s.Logger.Fatal("panic", nil, lager.Data{"message": fmt.Sprintf(format, v...)})
}

func (s Shim) Panicln(v ...interface{}) {
	s.Logger.Fatal("panic", nil, lager.Data{"message": fmt.Sprintln(v...)})
}

func (s Shim) Print(v ...interface{}) {
	s.Logger.Info("", nil, lager.Data{"message": fmt.Sprint(v...)})
}

func (s Shim) Printf(format string, v ...interface{}) {
	s.Logger.Info("", nil, lager.Data{"message": fmt.Sprintf(format, v...)})
}

func (s Shim) Println(v ...interface{}) {
	s.Logger.Info("", nil, lager.Data{"message": fmt.Sprintln(v...)})
}
