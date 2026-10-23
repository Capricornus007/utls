module github.com/metacubex/utls

go 1.28

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/andybalholm/brotli v1.2.6
	github.com/klauspost/compress v1.20.3 // lastest version compatible with golang1.20
	golang.org/x/crypto v0.58.0 // lastest version compatible with golang1.20
	golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e // lastest version compatible with golang1.20
)

require golang.org/x/sys v0.49.0 // indirect
