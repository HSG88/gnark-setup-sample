package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

type QAP struct {
	NConstraints, NWires, NPublic int32
	A, B, C                       [][]fr.Element
}

func (qap *QAP) New(ccs constraint.ConstraintSystem) {
	switch r1cs := ccs.(type) {
	case *cs_bn254.R1CS:
		internal, secret, public := r1cs.GetNbVariables()
		qap.NConstraints = int32(r1cs.GetNbConstraints())
		qap.NWires = int32(internal + secret + public)
		qap.NPublic = int32(public)

		qap.A = make([][]fr.Element, qap.NWires)
		qap.B = make([][]fr.Element, qap.NWires)
		qap.C = make([][]fr.Element, qap.NWires)

		for i := 0; i < int(qap.NWires); i++ {
			qap.A[i] = make([]fr.Element, qap.NConstraints)
			qap.B[i] = make([]fr.Element, qap.NConstraints)
			qap.C[i] = make([]fr.Element, qap.NConstraints)
		}

		for i, c := range r1cs.Constraints {
			if i == 330 {
				fmt.Println("Now")
			}
			for _, t := range c.L {
				if !qap.A[t.WireID()][i].IsZero() {
					fmt.Println("A")
				}
				qap.A[t.WireID()][i].Add(&qap.A[t.WireID()][i], &r1cs.Coefficients[t.CoeffID()])
			}
			for _, t := range c.R {
				if !qap.B[t.WireID()][i].IsZero() {
					fmt.Println("B")
				}
				qap.B[t.WireID()][i].Add(&qap.B[t.WireID()][i], &r1cs.Coefficients[t.CoeffID()])
			}
			for _, t := range c.O {
				if !qap.C[t.WireID()][i].IsZero() {
					fmt.Println("C")
				}
				qap.C[t.WireID()][i].Add(&qap.C[t.WireID()][i], &r1cs.Coefficients[t.CoeffID()])
			}
			fmt.Println(i)
		}
	default:
		panic("not supported curve")
	}
}

func (qap *QAP) Save(path string) {
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Write NConstraints, NWires, NPublic
	binary.Write(file, binary.LittleEndian, qap.NConstraints)
	binary.Write(file, binary.LittleEndian, qap.NWires)
	binary.Write(file, binary.LittleEndian, qap.NPublic)

	enc := bn254.NewEncoder(file)
	// Write A, B, C
	for i := 0; i < int(qap.NWires); i++ {
		err = enc.Encode(qap.A[i])
		if err != nil {
			panic(err)
		}
		err = enc.Encode(qap.B[i])
		if err != nil {
			panic(err)
		}
		err = enc.Encode(qap.C[i])
		if err != nil {
			panic(err)
		}
	}
}

func (qap *QAP) Load(path string) {
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Read NConstraints, NWires, NPublic
	binary.Read(file, binary.LittleEndian, &qap.NConstraints)
	binary.Read(file, binary.LittleEndian, &qap.NWires)
	binary.Read(file, binary.LittleEndian, &qap.NPublic)

	// Initialize A, B, C
	qap.A = make([][]fr.Element, qap.NWires)
	qap.B = make([][]fr.Element, qap.NWires)
	qap.C = make([][]fr.Element, qap.NWires)

	// Read A, B, C
	dec := bn254.NewDecoder(file)
	for i := 0; i < int(qap.NWires); i++ {
		qap.A[i] = make([]fr.Element, qap.NConstraints)
		qap.B[i] = make([]fr.Element, qap.NConstraints)
		qap.C[i] = make([]fr.Element, qap.NConstraints)

		err = dec.Decode(&qap.A[i])
		if err != nil {
			panic(err)
		}
		err = dec.Decode(&qap.B[i])
		if err != nil {
			panic(err)
		}
		err = dec.Decode(&qap.C[i])
		if err != nil {
			panic(err)
		}
	}
}
