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

var logger = shim.NewLogger("IdRegisterChaincode")

// IDRegisterChaincode ...Struct
type IDRegisterChaincode struct {
}

// IdentityModel ...Register Identity
type IdentityModel struct {
	Name             string `json:"name"`
	FatherName       string `json:"father_name"`
	MotherName       string `json:"mother_name"`
	EntityAccess     string `json:"entity_access"`
	Passport         string `json:"passport"`
	Ssn              string `json:"ssn_number"`
	BirthCertificate string `json:"bc_number"`
}

//Init ...Method
func (t *IDRegisterChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Debug("Init")
	return shim.Success(nil)
}

//Invoke ...Method
func (t *IDRegisterChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Debug("Invoke")
	function, args := stub.GetFunctionAndParameters()
	if function == "register" {
		return t.register(stub, args)
	} else if function == "query" {
		return t.query(stub, args)
	}

	return pb.Response{Status: 403, Message: "unknown function name"}
}

func (t *IDRegisterChaincode) register(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	creatorBytes, err := stub.GetCreator()
	if err != nil {
		return shim.Error("cannot get creator")
	}

	user, org := getCreator(creatorBytes)

	if org == "id-us" || org == "id-mx" {

		if strings.Contains(user, "admin") {
			if len(args) < 3 {
				return pb.Response{Status: 403, Message: "incorrect number of arguments"}
			}

			identityModelObj := &IdentityModel{
				Name:             args[0],
				FatherName:       args[1],
				MotherName:       args[2],
				EntityAccess:     args[3],
				Passport:         args[4],
				Ssn:              args[5],
				BirthCertificate: args[6]}

			identifier := args[0] + "@" + args[6]

			key := "did:" + org + ":" + fmt.Sprint(hash(identifier))

			jsonIdentityModelObj, err := json.Marshal(identityModelObj)
			if err != nil {
				return shim.Error("Cannot create Json Object")
			}
			logger.Debug("Json Obj: " + string(jsonIdentityModelObj))
			err = stub.PutState(key, jsonIdentityModelObj)
			if err != nil {
				return shim.Error("cannot put state")
			}
		} else {
			return pb.Response{Status: 403, Message: "Higher-access level required"}
		}

	}

	return shim.Success(nil)
}

func (t *IDRegisterChaincode) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if args[0] == "health" {
		logger.Info("Health status Ok")
		return shim.Success(nil)
	}

	creatorBytes, err := stub.GetCreator()
	if err != nil {
		return shim.Error("cannot get creator")
	}

	user, org := getCreator(creatorBytes)

	if org == "" {
		logger.Debug("Org is null")
		return shim.Error("cannot get Org")

	} else if org == "id-us" || org == "id-mx" {

		key := "did:" + org + ":"

		if len(args) == 2 {
			identifier := args[0] + "@" + args[1]

			key = key + fmt.Sprint(hash(identifier))
		} else {
			key = key + user
		}

		logger.Info("Key is: " + key)
		jsonIdentityModelObj, err := stub.GetState(key)
		if err != nil {
			return shim.Error("Cannot get State")
		}
		logger.Debug("Value: " + string(jsonIdentityModelObj))

		return shim.Success(jsonIdentityModelObj)

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
	err := shim.Start(new(IDRegisterChaincode))
	if err != nil {
		fmt.Printf("Error starting IDRegisterChaincode chaincode: %s", err)
	}
}
