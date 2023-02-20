package main

import (
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type Circuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// Hash = mimc(PreImage)
func (circuit *Circuit) Define(api frontend.API) error {
	// hash function
	mimc, _ := mimc.NewMiMC(api)

	// specify constraints
	// mimc(preImage) == hash
	mimc.Write(circuit.PreImage)
	api.AssertIsEqual(circuit.Hash, mimc.Sum())

	return nil
}

func ReadPKVK() (groth16.ProvingKey, groth16.VerifyingKey) {
	pk := groth16.NewProvingKey(ecc.BN254)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	pkFile, _ := os.Open("pk")
	defer pkFile.Close()

	pk.ReadFrom(pkFile)

	vkFile, _ := os.Open("vk")
	defer vkFile.Close()
	vk.ReadFrom(vkFile)
	return pk, vk
}

func main() {
	var myCircuit Circuit
	r1cs, _ := frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)

	// var qap *QAP = &QAP{}
	// qap.New(r1cs)
	// qap.Save("qap")

	//pk, vk, _ :=groth16.Setup(r1cs)
	pk, vk := ReadPKVK()
	assignment := &Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "12886436712380113721405259596386800092738845035233065858332878701083870690753",
	}
	witness, _ := frontend.NewWitness(assignment, bn254.ID.ScalarField())
	prf, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}
	pubWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(prf, vk, pubWitness)
	if err != nil {
		panic(err)
	}

}
