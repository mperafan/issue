package main

import (
	"crypto/sha256"
	"math/big"
	"math/rand"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	bn254cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test/unsafekzg"
)

type Packet struct { //circuit that represent merkle tree. the output is the proof of that all leafs belongs to the tree
	AggregatedPacketHash [32]uints.U8 `gnark:",public"`  //Public hash
	AggregatedPacket     []byte       `gnark:",private"` //Packet
}

func (circuit *Packet) Define(api frontend.API) error { //function where i calculate the root and if the packethash and packet are the same
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	hpacket := sha256.New()
	hpacket.Write(circuit.AggregatedPacket)
	res := bytetouint(hpacket.Sum(make([]byte, 0)))
	for k := range circuit.AggregatedPacketHash {
		uapi.ByteAssertEq(circuit.AggregatedPacketHash[k], res[k])
	}
	return nil
}

func getBytes(b *big.Int) []byte { //function to get bytes
	const SIZE = 32
	bElement := fr.NewElement(b.Uint64())
	res := make([]byte, SIZE)
	for i := 0; i < SIZE; i++ {
		res[i] = bElement.Bytes()[i]
	}
	return res
}

func bytetouint(PacketBytes []byte) [32]uints.U8 { //function to convert bytes to uint
	aux := uints.NewU8Array(PacketBytes)
	var Packetaux [32]uints.U8
	for j := 0; j < min(32, len(aux)); j++ {
		Packetaux[j] = aux[j]
	}
	return Packetaux
}

func min(a, b int) int { //function of min, necesary for the func bytetouint
	if a > b {
		return b
	}
	return a
}

func Proof() Packet { //function where i calculate the variable for the proof
	var Pack Packet
	Pack.AggregatedPacket = getBytes(big.NewInt(rand.Int63n(int64(1e18))))
	shaa2 := sha256.New()
	shaa2.Write(Pack.AggregatedPacket)
	Pack.AggregatedPacketHash = bytetouint(shaa2.Sum(make([]byte, 0)))
	return Pack
}

func main() {
	packetaux := Proof()
	assignment := &packetaux
	var myCircuit2 Packet
	cs, _ := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &myCircuit2)
	scs := cs.(*bn254cs.SparseR1CS)
	srs, srsLagrange, _ := unsafekzg.NewSRS(scs)
	pk, vk, _ := plonk.Setup(cs, srs, srsLagrange)
	witness, errNW := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if errNW != nil {
		panic(errNW)
	}
	proof, errProve := plonk.Prove(cs, pk, witness)
	if errProve != nil {
		panic(errProve)
	}
	pubWitness, _ := witness.Public()
	err := plonk.Verify(proof, vk, pubWitness)
	if err != nil {
		panic(err)
	}

}
