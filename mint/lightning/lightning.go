package lightning

import (
	"log"
	"os"
)

const (
	LND = "Lnd"
)

type Client interface {
	CreateInvoice(amount uint64) (Invoice, error)
	InvoiceSettled(hash string) bool
}

func NewLightningClient() Client {
	backend := os.Getenv("LIGHTNING_BACKEND")

	switch backend {
	case LND:
		lndClient, err := CreateLndClient()
		if err != nil {
			log.Fatalf("error setting up lightning backend: %v", err)
		}
		return lndClient

	default:
		log.Fatal("please specify a lignting backend")
	}

	return nil
}

type Invoice struct {
	Id             string // random id generated by mint
	PaymentRequest string
	PaymentHash    string
	Settled        bool
	Redeemed       bool
	Amount         uint64
	Expiry         int64 // in unix timestamp
}
