package main

type Config struct {
	Port            int    `default:"8081"`
	MasterJWTSecret []byte `required:"true"`
	ScopedJWTSecret []byte `required:"true"`
}
