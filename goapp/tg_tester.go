package main

import (
	"fmt"
	"reflect"

	"github.com/gotd/td/telegram/query/dialogs"
)

func main() {
	var e dialogs.Elem
	t := reflect.TypeOf(&e.Entities)
	for i := 0; i < t.NumMethod(); i++ {
		fmt.Printf("func %s%s\n", t.Method(i).Name, t.Method(i).Type.String()[4:])
	}
}
