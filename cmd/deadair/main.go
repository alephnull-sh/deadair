package main

import (
	"os"
	_ "time/tzdata"

	"github.com/alephnull-sh/deadair/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
