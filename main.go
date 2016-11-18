package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"syscall"

	"github.com/jamescun/onepass/onepass"

	"golang.org/x/crypto/ssh/terminal"
)

var (
	Path = flag.String("path", "/home/me/Dropbox/1Password.agilekeychain", "path to 1Password keychain")
)

func main() {
	flag.Parse()

	items, err := onepass.LoadItemsDir(filepath.Join(*Path, "data/default"))
	if err != nil {
		panic(err)
	}

	keychain, err := onepass.LoadKeychainFile(filepath.Join(*Path, "data/default/encryptionKeys.js"))
	if err != nil {
		panic(err)
	}

	ak := &onepass.AgileKeychain{
		Items:    items,
		Keychain: keychain,
	}

	fmt.Print("master password: ")
	masterPassword, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		panic(err)
	}
	fmt.Print("\n")

	err = ak.Unlock(masterPassword)
	if err != nil {
		panic(err)
	}

	query := items
	args := flag.Args()
	if len(args) > 0 {
		query = query.Match(args[0])
	}

	for _, item := range query {
		fmt.Printf(
			"\nUUID:     %s\nType:     %s\nTitle:    %s\nLocation: %s\nCreated:  %s\nUpdated:  %s\n",
			item.UUID, item.Type, item.Title, item.Location, item.CreatedAt, item.UpdatedAt)

		secrets, err := ak.Decrypt(item)
		if err != nil {
			panic(err)
		}

		switch secrets := secrets.(type) {
		case *onepass.Login:
			fmt.Print("URLs:\n")
			for _, url := range secrets.URLs {
				fmt.Printf("  - %s\n", url.URL)
			}

			fmt.Print("Secrets:\n")
			for _, field := range secrets.Fields {
				fmt.Printf("  - %s: %s\n", field.Name, field.Value)
			}

		case *onepass.CreditCard:
			fmt.Printf(
				"Credit Card:\n  Issuer:     %s\n  Cardholder: %s\n  Number:     %s\n  CVV:        %s\n  PIN:        %s\n  Expiry:     %s/%s\n",
				secrets.Issuer, secrets.Cardholder, secrets.Number, secrets.CVV, secrets.PIN, secrets.ExpiryMonth, secrets.ExpiryYear)
		}
	}
}
