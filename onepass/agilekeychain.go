package onepass

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Key struct {
	Id         string `json:"identifier"`
	Level      string `json:"level"`
	Iterations int    `json:"iterations"`

	Data       string `json:"data"`
	Validation string `json:"validation"`

	encryptionKey []byte
}

func (k *Key) Lock() error {
	k.encryptionKey = nil
	return nil
}

func (k *Key) Unlock(masterPassword []byte) error {
	iterations := k.Iterations
	if iterations < 1000 {
		// minimum of 1000 iterations unless otherwise configured
		iterations = 1000
	}

	keyEncrypted, err := base64.StdEncoding.DecodeString(strings.TrimRightFunc(k.Data, isNonPrinting))
	if err != nil {
		return err
	}

	keyData := salted(keyEncrypted)

	derivedKey := PBKDF2(masterPassword, keyData.Salt(), iterations)

	aesKey := derivedKey[:16]
	aesIv := derivedKey[16:]

	k.encryptionKey, err = decrypt(aesKey, aesIv, keyData.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func isNonPrinting(r rune) bool {
	return r < '\x20'
}

func (k *Key) Decrypt(saltedData []byte) ([]byte, error) {
	if k.encryptionKey == nil {
		return nil, ErrLocked
	}

	data := salted(saltedData)
	key, iv := deriveOpenSSL(k.encryptionKey, data.Salt())

	raw, err := decrypt(key, iv, data.Bytes())
	return bytes.TrimRightFunc(raw, isNonPrinting), err
}

type Keychain struct {
	SL3 string `json:"SL3"`
	SL5 string `json:"SL5"`

	Keys []*Key `json:"list"`
}

func LoadKeychain(r io.Reader) (*Keychain, error) {
	k := new(Keychain)
	err := json.NewDecoder(r).Decode(&k)
	if err != nil {
		return nil, err
	}

	return k, nil
}

func LoadKeychainFile(path string) (*Keychain, error) {
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	k, err := LoadKeychain(file)
	return k, err
}

func (k *Keychain) GetId(id string) *Key {
	for _, key := range k.Keys {
		if key.Id == id {
			return key
		}
	}

	return nil
}

func (k *Keychain) GetLevel(level string) *Key {
	if level == "" {
		level = "SL5"
	}

	switch level {
	case "SL3":
		x := k.GetId(k.SL3)
		if x != nil {
			return x
		}

	case "SL5":
		x := k.GetId(k.SL5)
		if x != nil {
			return x
		}
	}

	for _, key := range k.Keys {
		if key.Level == level {
			return key
		}
	}

	return nil
}

func (k *Keychain) LockAll() error {
	for _, key := range k.Keys {
		key.encryptionKey = nil
	}

	return nil
}

func (k *Keychain) UnlockAll(masterPassword []byte) error {
	for _, key := range k.Keys {
		if key.encryptionKey == nil {
			err := key.Unlock(masterPassword)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (k *Keychain) Decrypt(level string, saltedData []byte) ([]byte, error) {
	key := k.GetLevel(level)
	if key == nil {
		return nil, ErrNoSecurityLevel
	}

	plaintext, err := key.Decrypt(saltedData)
	return plaintext, err
}

type Item struct {
	UUID       string `json:"uuid"`
	FolderUUID string `json:"folderUuid"`

	Type     string `json:"typeName"`
	Title    string `json:"title"`
	LocKey   string `json:"locationKey"`
	Location string `json:"location"`

	Level     string `json:"securityLevel"`
	Checksum  string `json:"contentsHash"`
	Encrypted string `json:"encrypted"`

	CreatedAt Timestamp `json:"createdAt"`
	UpdatedAt Timestamp `json:"updatedAt"`
}

func LoadItem(r io.Reader) (*Item, error) {
	item := new(Item)
	err := json.NewDecoder(r).Decode(item)
	if err != nil {
		return nil, err
	}

	return item, nil
}

func LoadItemFile(path string) (*Item, error) {
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	i, err := LoadItem(file)
	return i, err
}

func (i *Item) Match(s string) bool {
	if i.UUID == s {
		return true
	} else if strings.Contains(i.Title, s) {
		return true
	} else if strings.Contains(i.LocKey, s) {
		return true
	} else if strings.Contains(i.Location, s) {
		return true
	}

	return false
}

type Items []*Item

func LoadItemsDir(path string) (Items, error) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var items Items

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".1password") {
			item, err := LoadItemFile(filepath.Join(path, file.Name()))
			if err != nil {
				return nil, err
			}

			items = append(items, item)
		}
	}

	return items, nil
}

func (i Items) Match(s string) Items {
	res := i[:0]

	for _, item := range i {
		if item.Match(s) {
			res = append(res, item)
		}
	}

	return res
}

func (i Items) Type(t string) Items {
	res := i[:0]

	for _, item := range i {
		if item.Type == t {
			res = append(res, item)
		}
	}

	return res
}

type Secrets interface {
	Type() string
}

type Login struct {
	URLs   []URL   `json:"URLs"`
	Fields []Field `json:"fields"`
}

func (l *Login) Type() string {
	return "webform.WebForm"
}

type URL struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type Field struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Designation string `json:"designation"`
}

type CreditCard struct {
	Issuer string `json:"type"`

	Number     string `json:"ccnum"`
	Cardholder string `json:"cardholder"`
	CVV        string `json:"cvv"`
	PIN        string `json:"pin"`

	ExpiryMonth string `json:"expiry_mm"`
	ExpiryYear  string `json:"expiry_yy"`
}

func (c *CreditCard) Type() string {
	return "wallet.financial.CreditCard"
}

type AgileKeychain struct {
	Items    Items
	Keychain *Keychain
}

func (ak *AgileKeychain) Lock() error {
	err := ak.Keychain.LockAll()
	return err
}

func (ak *AgileKeychain) Unlock(masterPassword []byte) error {
	err := ak.Keychain.UnlockAll(masterPassword)
	return err
}

func (ak *AgileKeychain) Decrypt(item *Item) (Secrets, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimRightFunc(item.Encrypted, isNonPrinting))
	if err != nil {
		return nil, err
	}

	plaintext, err := ak.Keychain.Decrypt(item.Level, ciphertext)
	if err != nil {
		return nil, err
	}

	var body Secrets

	switch item.Type {
	case "webforms.WebForm":
		body = new(Login)

	case "wallet.financial.CreditCard":
		body = new(CreditCard)

	default:
		return nil, fmt.Errorf("unsupported type '%s'", item.Type)
	}

	err = json.Unmarshal(plaintext, body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

type Timestamp struct {
	time.Time
}

func (t *Timestamp) MarshalJSON() ([]byte, error) {
	s := strconv.FormatInt(t.Unix(), 10)
	return []byte(s), nil
}

func (t *Timestamp) UnmarshalJSON(p []byte) error {
	n, err := strconv.ParseInt(string(p), 10, 64)
	if err != nil {
		return err
	}

	t.Time = time.Unix(n, 0)
	return nil
}
