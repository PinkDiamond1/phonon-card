package cardtests

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/GridPlus/phonon-client/card"
	"github.com/GridPlus/phonon-client/cert"
	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/orchestrator"
	"github.com/sirupsen/logrus"
)

//helper functions
func resetCardState() {
	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatal("unable to retrieve current directory")
	}
	err = os.Chdir("../../")
	if err != nil {
		log.Fatal("unable to change directory to build")
	}
	output, err := exec.Command("make", "install-card").Output()
	if err != nil {
		fmt.Println(string(output))
		log.Fatal(err)
	}
	os.Chdir(currentDir)
}

func getCardHappy() *card.PhononCommandSet {
	resetCardState()
	cs, err := card.Connect(0)
	if err != nil {
		log.Fatal("unable to connect to first card" + err.Error())
	}
	return cs
}

func selectHappy() *card.PhononCommandSet {
	cs := getCardHappy()
	_, _, _, err := cs.Select()
	if err != nil {
		log.Fatal("unable to select applet" + err.Error())
	}
	return cs
}

func installCertHappy() *card.PhononCommandSet {
	cs := selectHappy()
	err := cs.InstallCertificate(cert.SignWithDemoKey)
	if err != nil {
		log.Fatal("unable to install card cert" + err.Error())
	}
	return cs
}

func setPinHappy() *card.PhononCommandSet {
	cs := installCertHappy()
	err := cs.Init("111111")
	if err != nil {
		log.Fatal("unable to set pin" + err.Error())
	}
	return cs
}

func pairWithTerminalHappy() *card.PhononCommandSet {
	cs := setPinHappy()
	cs.Select()
	_, err := cs.Pair()
	if err != nil {
		log.Fatal("unable to pair locally" + err.Error())
	}
	err = cs.OpenSecureChannel()
	if err != nil {
		log.Fatal("unable to open secure channel" + err.Error())
	}
	return cs
}

func unlockHappy() *card.PhononCommandSet {
	cs := pairWithTerminalHappy()
	err := cs.VerifyPIN("111111")
	if err != nil {
		log.Fatal("unable to unlock card" + err.Error())
	}
	return cs
}

func createPhononHappy(num int) *card.PhononCommandSet {
	cs := unlockHappy()
	for i := 0; i < num; i++ {
		_, _, err := cs.CreatePhonon(model.Secp256k1)
		if err != nil {
			log.Fatal("unable to create phonons" + err.Error())
		}
	}
	return cs
}

func setDescriptorHappy(num int) *card.PhononCommandSet {
	cs := createPhononHappy(num)
	for i := 0; i < num; i++ {
		phon := model.Phonon{
			KeyIndex:     uint16(i + 1),
			Denomination: model.Denomination{Base: 1, Exponent: 1},
			CurrencyType: model.Bitcoin,
		}
		err := cs.SetDescriptor(&phon)
		if err != nil {
			log.Fatal(fmt.Sprintf("Unable to set descriptor for phonon: %+v, %s", phon, err.Error()))
		}
	}
	return cs
}

func cardPairHappy() (*card.PhononCommandSet, *orchestrator.Session, *orchestrator.Session) {
	cs := setPinHappy()
	term := orchestrator.NewPhononTerminal()
	card, err := orchestrator.NewSession(cs)
	if err != nil {
		log.Fatal("Unable to generate sesison from card")
	}
	term.AddSession(card)
	card.VerifyPIN("111111")
	mockid, err := term.GenerateMock()
	if err != nil {
		log.Fatal("Unable to generate mock for pairing")
	}
	mock := term.SessionFromID(mockid)
	mock.VerifyPIN("111111")
	err = mock.ConnectToLocalProvider()
	if err != nil {
		log.Fatal("Unable to connect mock to local provider for pairing")
	}
	err = card.ConnectToLocalProvider()
	if err != nil {
		log.Fatal("Unable to connect to local provider")
	}
	err = mock.ConnectToCounterparty(card.GetName())
	if err != nil {
		log.Fatal("unable to connect mock session to local counterparty for pairing")
	}
	err = card.ConnectToCounterparty(mockid)
	if err != nil {
		log.Fatal("Unable to Pair card to mock")
	}
	return cs, card, mock
}

//todo: attempt to create a phonon with curve type above avilable ones
// should fail
//todo: create a phonon with curve type higher than max on counterparty. send to card
// should be received and transacted with fine

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}
