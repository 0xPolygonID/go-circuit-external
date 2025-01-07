package gocircuitexternal

import (
	"reflect"
	"sync"

	"github.com/iden3/go-circuits/v2"
)

const (
	AnonAadhaarV1 circuits.CircuitID = "anonAadhaarV1"
)

var circuitsRegistry = map[circuits.CircuitID]circuits.Data{}
var circuitsLock = new(sync.RWMutex)

// RegisterCircuit is factory for circuit init.
// This is done during init() in the method's implementation
func RegisterCircuit(id circuits.CircuitID, c circuits.Data) {
	circuitsLock.Lock()
	defer circuitsLock.Unlock()

	circuitsRegistry[id] = c
}

//nolint:gochecknoinits // this is the way to register circuits
func init() {
	// Use a custom registry to avoid registering external circuits in the internal registry
	RegisterCircuit(AnonAadhaarV1, circuits.Data{
		Input:  &AnonAadhaarV1Inputs{},
		Output: &AnonAadhaarV1PubSignals{},
	})
}

// UnmarshalCircuitOutput unmarshal bytes to specific circuit Output type associated with id
func UnmarshalCircuitOutput(id circuits.CircuitID, b []byte) (map[string]interface{}, error) {
	circuitsLock.RLock()
	defer circuitsLock.RUnlock()

	circuitOutputType, exist := circuitsRegistry[id]
	if !exist {
		return nil, circuits.ErrorCircuitIDNotFound
	}

	typ := reflect.TypeOf(circuitOutputType.Output)
	val := reflect.New(typ.Elem())

	newPointer := val.Interface()

	err := newPointer.(circuits.PubSignalsUnmarshaller).PubSignalsUnmarshal(b)
	if err != nil {
		return nil, err
	}

	m := newPointer.(circuits.PubSignalsMapper).GetObjMap()

	return m, nil
}

// GetCircuit return circuit Data
func GetCircuit(id circuits.CircuitID) (*circuits.Data, error) {
	circuitsLock.RLock()
	defer circuitsLock.RUnlock()

	circuit, ok := circuitsRegistry[id]
	if !ok {
		return nil, circuits.ErrorCircuitIDNotFound
	}
	return &circuit, nil
}
