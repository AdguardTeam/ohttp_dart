# Start local OHTTP gateway (debug only).
# Requires Go 1.25+ — see scripts/local_ohttp_gw/main.go.
ohttp-gw:
	cd scripts/local_ohttp_gw && go run .
