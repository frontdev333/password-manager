package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const ErrWeakPassword = "password length must be at least 8 characters"
const ErrPasswordManagerNotInit = "password manager is not initialized"

type Password struct {
	Name         string    `json:"name"`          // Название сервиса или сайта
	Value        string    `json:"value"`         // Значение пароля
	Category     string    `json:"category"`      // Категория для группировки (например: "social", "work", "finance")
	CreatedAt    time.Time `json:"created_at"`    // Дата создания записи
	LastModified time.Time `json:"last_modified"` // Дата последнего изменения
}

type PasswordManager struct {
	passwords     map[string]Password `json:"passwords"` // Хранилище паролей, где ключ - название сервиса
	masterKey     []byte              `json:"-"`         // Главный ключ шифрования, используется для защиты всех паролей
	filePath      string              `json:"-"`         // Путь к файлу для хранения зашифрованных данных
	isInitialized bool                `json:"-"`         // Флаг, показывающий установлен ли мастер-пароль
}

func NewPassword(name, value, category string) Password {
	return Password{
		Name:         name,
		Value:        value,
		Category:     category,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
}

func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		passwords:     make(map[string]Password),
		masterKey:     nil,
		filePath:      filePath,
		isInitialized: false,
	}
}

func (pm *PasswordManager) GeneratePassword(length int) (string, error) {
	if length < 8 {
		return "", errors.New(ErrWeakPassword)
	}

	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()[]{}';:,./\\`=-"
	const charsLen = len(chars)
	randBytes := make([]byte, length)

	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}

	var result strings.Builder

	for _, v := range randBytes {
		i := int(v) % charsLen
		result.WriteByte(chars[i])
	}
	return result.String(), nil
}

func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if pm.isInitialized != true {
		return errors.New(ErrPasswordManagerNotInit)
	}

	_, ok := pm.passwords[name]
	if ok {
		return errors.New("password for this service already exists")
	}

	pass := NewPassword(name, value, category)
	pm.passwords[name] = pass

	return nil

}

func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.isInitialized {
		return Password{}, errors.New(ErrPasswordManagerNotInit)
	}

	pass, ok := pm.passwords[name]
	if !ok {
		return Password{}, errors.New("password not found")
	}
	return pass, nil
}

func (pm *PasswordManager) ListPasswords() []Password {
	tmpPassSlice := make([]Password, 0, len(pm.passwords))

	for _, v := range pm.passwords {
		tmpPassSlice = append(tmpPassSlice, v)
	}

	return tmpPassSlice
}

func (pm *PasswordManager) SetMasterPassword(masterPassword string) error {
	if len(masterPassword) < 8 {
		return errors.New(ErrWeakPassword)
	}

	keyBytes := make([]byte, 32)

	copy(keyBytes, []byte(masterPassword))

	pm.masterKey = keyBytes
	pm.isInitialized = true

	return nil
}

func (pm *PasswordManager) SaveToFile() error {
	if !pm.isInitialized {
		return errors.New(ErrPasswordManagerNotInit)
	}

	data, err := json.Marshal(pm.passwords)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	encryptedData := make([]byte, len(data))
	stream.XORKeyStream(encryptedData, data)

	file, err := os.Create(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err = file.Write(iv); err != nil {
		return err
	}

	if _, err = file.Write(encryptedData); err != nil {
		return err
	}

	return nil
}

func (pm *PasswordManager) LoadFromFile() error {
	file, err := os.Open(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(file, iv); err != nil {
		return err
	}

	encryptedData, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	decryptedData := make([]byte, len(encryptedData))
	stream.XORKeyStream(decryptedData, encryptedData)

	return json.Unmarshal(decryptedData, &pm.passwords)
}

func (pm *PasswordManager) CheckPasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.New(ErrWeakPassword)
	}

	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*", char):
			hasSpecial = true
		}
	}

	if hasUpper && hasLower && hasNumber && hasSpecial {
		return nil
	}

	return errors.New("password is too weak")
}

func (pm *PasswordManager) GetPasswordsByCategory(category string) []Password {
	var res []Password

	for _, v := range pm.passwords {
		if v.Category == category {
			res = append(res, v)
		}
	}

	return res
}

func (pm *PasswordManager) FindDuplicatePasswords() map[string][]string {
	groups := make(map[string][]string)
	duplicates := make(map[string][]string)

	for _, v := range pm.passwords {
		groups[v.Value] = append(groups[v.Value], v.Name)
	}

	for k, v := range groups {
		if len(v) > 1 {
			duplicates[k] = v
		}
	}

	return duplicates
}

func main() {
	pm := NewPasswordManager("test.dat")
	pm.isInitialized = true // Для демонстрации

	// Добавляем пароли, некоторые с одинаковыми значениями
	pm.SavePassword("github.com", "StrongPass123!", "dev")
	pm.SavePassword("gmail.com", "UniquePass456!", "email")
	pm.SavePassword("gitlab.com", "StrongPass123!", "dev") // дубликат
	pm.SavePassword("netflix.com", "DifferentPass789!", "entertainment")
	pm.SavePassword("amazon.com", "StrongPass123!", "shopping") // дубликат

	// Ищем дубликаты
	duplicates := pm.FindDuplicatePasswords()

	if len(duplicates) == 0 {
		fmt.Println("Duplicates not found")
	} else {
		fmt.Printf("\nFound duplicates:\n")
		for password, services := range duplicates {
			fmt.Printf("\nPassword '%s' is used in the following services:\n", password)
			for _, service := range services {
				fmt.Printf("- %s\n", service)
			}
		}
	}
}
