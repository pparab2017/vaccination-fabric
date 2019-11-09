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

var logger = shim.NewLogger("VaccinatePerson")

// VaccinatePerson ...
type VaccinatePerson struct {
}

// VaccinationRecord ...
type VaccinationRecord struct {
	DocName             string `json:"doc_name"`
	DocLicNbr           string `json:"doc_lic_nbr"`
	PatientName         string `json:"patient_name"`
	PatientBirthCertNbr string `json:"patient_bc_nbr"`
	VaccinationDetails  string `json:"vaccination_details"`
	VaccinationDate     string `json:"vaccination_date"`
}

// VaccineAdmin ...Model
type VaccineAdmin struct {
	Name          string `json:"name"`
	LicenceNumber string `json:"lic_no"`
	LicenceEntity string `json:"entity"`
}

//Init ...Method
func (t *VaccinatePerson) Init(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Debug("Init")
	return shim.Success(nil)
}

//Invoke ...Method
func (t *VaccinatePerson) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Debug("Invoke")
	function, args := stub.GetFunctionAndParameters()
	if function == "vaccinate" {
		return t.vaccinate(stub, args)
	} else if function == "query" {
		return t.query(stub, args)
	}

	return pb.Response{Status: 403, Message: "unknown function name"}
}

func (t *VaccinatePerson) vaccinate(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	creatorBytes, err := stub.GetCreator()
	if err != nil {
		return shim.Error("cannot get creator")
	}

	user, org := getCreator(creatorBytes)
	if org == "vacci-us" || org == "vacci-mx" {

		if strings.Contains(user, "hospital") {

			funcCall := []byte("queryForDoctor")

			dealerKey := []byte(fmt.Sprint(hash(args[0] + "@" + args[1])))
			argTocc := [][]byte{funcCall, dealerKey}

			response := stub.InvokeChaincode("vacci-admin", argTocc, "medi-council-us")

			payloadBytes := response.GetPayload()

			logger.Info(string(payloadBytes))

			var vaccinatePersonObj VaccinatePerson
			errUnmarshal := json.Unmarshal([]byte(payloadBytes), &vaccinatePersonObj)
			if errUnmarshal != nil {
				return shim.Error("Could not find Doctor record - Cannot add vaccination Record")
			}

			vaccinationRecordObj := &VaccinationRecord{
				DocName:             args[0],
				DocLicNbr:           args[1],
				PatientName:         args[2],
				PatientBirthCertNbr: args[3],
				VaccinationDetails:  args[4],
				VaccinationDate:     args[5]}

			identifier := args[2] + "@" + args[3]

			key := "did:" + org + ":" + fmt.Sprint(hash(identifier))

			jsonVaccinationRecordObj, err := json.Marshal(vaccinationRecordObj)
			if err != nil {
				return shim.Error("Cannot create Json Object")
			}
			logger.Debug("Json Obj: " + string(jsonVaccinationRecordObj))
			err = stub.PutState(key, jsonVaccinationRecordObj)
			if err != nil {
				return shim.Error("cannot put state")
			}

		} else {
			return pb.Response{Status: 403, Message: "User has to be registered in Hospital"}
		}

	} else {
		return pb.Response{Status: 403, Message: "User has to be registered with Vaccination Org"}
	}

	return shim.Success(nil)
}

func (t *VaccinatePerson) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {

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

	} else if org == "vacci-us" || org == "vacci-mx" {

		key := "did:" + org + ":"

		if len(args) == 2 {
			identifier := args[0] + "@" + args[1]

			key = key + fmt.Sprint(hash(identifier))
		} else {
			key = key + user
		}

		logger.Info("Key is: " + key)
		jsonVaccinatePersonObj, err := stub.GetState(key)
		if err != nil {
			return shim.Error("Cannot get State")
		}
		logger.Debug("Value: " + string(jsonVaccinatePersonObj))

		return shim.Success(jsonVaccinatePersonObj)

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
	err := shim.Start(new(VaccinatePerson))
	if err != nil {
		fmt.Printf("Error starting VaccinatePerson chaincode: %s", err)
	}
}
