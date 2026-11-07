package main

import "fmt"

type checksum struct{ v string }

func (c checksum) String() string { return c.v }

func main() {
	md5 := checksum{v: "abc"}
	fmt.Println(md5.String())
}
