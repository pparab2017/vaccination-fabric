package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

var logger = shim.NewLogger("GlobalIdentity")

// GlobalIdentity ...
type GlobalIdentity struct {
}

//GlobalIdentityModel ...
type GlobalIdentityModel struct {
	PersonIdentifier      string `json:"person_identifier"`
	VaccinationIdentifier string `json:"vaccination_identifier"`
}

//Init ...Method
func (t *GlobalIdentity) Init(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Debug("Init")
	return shim.Success(nil)
}

//Invoke ...Method
func (t *GlobalIdentity) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Debug("Invoke")
	function, args := stub.GetFunctionAndParameters()
	if function == "vaccinate" {
		//return t.validate(stub, args)
	} else if function == "query" {
		return t.query(stub, args)
	}

	return pb.Response{Status: 403, Message: "unknown function name"}
}

func (t *GlobalIdentity) addID(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	globalIdentityModelObj := &GlobalIdentityModel{
		PersonIdentifier:      args[0],
		VaccinationIdentifier: args[1]}

	key := args[0]

	jsonGlobalIdentityModelObj, err := json.Marshal(globalIdentityModelObj)
	if err != nil {
		return shim.Error("Cannot create Json Object")
	}
	logger.Debug("Json Obj: " + string(jsonGlobalIdentityModelObj))
	err = stub.PutState(key, jsonGlobalIdentityModelObj)
	if err != nil {
		return shim.Error("cannot put state")
	}

	return shim.Success(nil)
}

func (t *GlobalIdentity) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if args[0] == "health" {
		logger.Info("Health status Ok")
		return shim.Success(nil)
	}

	creatorBytes, err := stub.GetCreator()
	if err != nil {
		return shim.Error("cannot get creator")
	}

	user, org := getCreator(creatorBytes)

	logger.Debug("User: " + user)

	if org == "" {
		logger.Debug("Org is null")
		return shim.Error("cannot get Org")

	} else if org == "id-us" || org == "id-mx" {
		key := "did:" + org + ":" + fmt.Sprint(hash(args[0]+"@"+args[1]))

		logger.Info("Key is: " + key)
		jsonGlobalIdentityModelObj, err := stub.GetState(key)
		if err != nil {
			return shim.Error("Cannot get State")
		}
		logger.Debug("Value: " + string(jsonGlobalIdentityModelObj))

		return shim.Success(jsonGlobalIdentityModelObj)

	}
	return shim.Success(nil)
}

var getCreator = func(certificate []byte) (string, string) {
	data := certificate[strings.Index(string(certificate), "-----") : strings.LastIndex(string(certificate), "-----")+5]
	block, _ := pem.Decode([]byte(data))
	cert, _ := x509.ParseCertificate(block.Bytes)
	organization := cert.Issuer.Organization[0]
	commonName := cert.Subject.CommonName
	logger.Debug("commonName: " + commonName + ", organization: " + organization)
	organizationShort := strings.Split(organization, ".")[0]

	return commonName, organizationShort
}

func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}
func main() {
	err := shim.Start(new(GlobalIdentity))
	if err != nil {
		fmt.Printf("Error starting GlobalIdentity chaincode: %s", err)
	}
}
