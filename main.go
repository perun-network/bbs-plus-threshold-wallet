package main

import (
	"github.com/perun-network/bbs-plus-threshold-wallet/measurements"
)

const (
	endpointAlice = "localhost:26602"
)

func main() {
	measurements.SimpleMeasurementWithCoefficientComputation()

}
