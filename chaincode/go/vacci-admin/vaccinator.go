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

var logger = shim.NewLogger("VaccinationAdministrator")

//VaccinationAdministrator ...
type VaccinationAdministrator struct {
}

// VaccineAdmin ...Model
type VaccineAdmin struct {
	Name          string `json:"name"`
	LicenceNumber string `json:"lic_no"`
	LicenceEntity string `json:"entity"`
}

//Init ...Method
func (t *VaccinationAdministrator) Init(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Debug("Init")
	return shim.Success(nil)
}

//Invoke ...Method
func (t *VaccinationAdministrator) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Debug("Invoke")
	function, args := stub.GetFunctionAndParameters()
	if function == "register" {
		return t.register(stub, args)
	} else if function == "query" {
		return t.query(stub, args)
	} else if function == "queryForDoctor" {
		return t.queryForDoctor(stub, args)
	}

	return pb.Response{Status: 403, Message: "unknown function name"}
}

func (t *VaccinationAdministrator) register(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	creatorBytes, err := stub.GetCreator()
	if err != nil {
		return shim.Error("cannot get creator")
	}

	user, org := getCreator(creatorBytes)

	if org == "mc-us" || org == "mc-mx" {

		if strings.Contains(user, "admin") {
			if len(args) < 3 {
				return pb.Response{Status: 403, Message: "incorrect number of arguments"}
			}

			vaccineAdminObj := &VaccineAdmin{
				Name:          args[0],
				LicenceNumber: args[1],
				LicenceEntity: args[2]}

			identifier := args[0] + "@" + args[1]

			key := "did:" + org + ":" + fmt.Sprint(hash(identifier))

			jsonVaccineAdminObj, err := json.Marshal(vaccineAdminObj)
			if err != nil {
				return shim.Error("Cannot create Json Object")
			}
			logger.Debug("Json Obj: " + string(jsonVaccineAdminObj))
			err = stub.PutState(key, jsonVaccineAdminObj)
			if err != nil {
				return shim.Error("cannot put state")
			}
		} else {
			return pb.Response{Status: 403, Message: "Higher-access level required"}
		}

	}

	return shim.Success(nil)
}

func (t *VaccinationAdministrator) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {

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

	} else if org == "mc-us" || org == "mc-mx" {

		key := "did:" + org + ":"

		if len(args) == 2 {
			identifier := args[0] + "@" + args[1]

			key = key + fmt.Sprint(hash(identifier))
		} else {
			key = key + user
		}

		logger.Info("Key is: " + key)
		jsonVaccineAdminObj, err := stub.GetState(key)
		if err != nil {
			return shim.Error("Cannot get State")
		}
		logger.Debug("Value: " + string(jsonVaccineAdminObj))

		return shim.Success(jsonVaccineAdminObj)

	}
	return shim.Success(nil)
}

func (t *VaccinationAdministrator) queryForDoctor(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	key := "did:" + "mc-us" + ":"

	if len(args) == 1 {
		identifier := args[0]

		key = key + identifier
	}

	logger.Info("Key is: " + key)
	jsonVaccineAdminObj, err := stub.GetState(key)
	if err != nil {
		return shim.Error("Cannot get State")
	}
	logger.Debug("Value: " + string(jsonVaccineAdminObj))

	return shim.Success(jsonVaccineAdminObj)

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
	err := shim.Start(new(VaccinationAdministrator))
	if err != nil {
		fmt.Printf("Error starting VaccinationAdministrator chaincode: %s", err)
	}
}
